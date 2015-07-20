//
//  SUIDGuard.c
//  SUIDGuard
//
//  Created by Stefan Esser on 15/07/15.
//  Copyright (c) 2015 SektionEins GmbH. All rights reserved.
//

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>


/* we have to copy these structs because we need access to fg_cred */

/* file types */
typedef enum {
    DTYPE_VNODE 	= 1,	/* file */
    DTYPE_SOCKET,		/* communications endpoint */
    DTYPE_PSXSHM,		/* POSIX Shared memory */
    DTYPE_PSXSEM,		/* POSIX Semaphores */
    DTYPE_KQUEUE,		/* kqueue */
    DTYPE_PIPE,		/* pipe */
    DTYPE_FSEVENTS,		/* fsevents */
    DTYPE_ATALK		/* (obsolete) */
} file_type_t;

struct fileglob {
    LIST_ENTRY(fileglob) f_msglist;/* list of active files */
    int32_t	fg_flag;		/* see fcntl.h */
    int32_t	fg_count;	/* reference count */
    int32_t	fg_msgcount;	/* references from message queue */
    int32_t fg_lflags;	/* file global flags */
    kauth_cred_t fg_cred;	/* credentials associated with descriptor */
    const struct fileops {
        file_type_t	fo_type;	/* descriptor type */
        int	(*fo_read)	(struct fileproc *fp, struct uio *uio,
                         int flags, vfs_context_t ctx);
        int	(*fo_write)	(struct fileproc *fp, struct uio *uio,
                         int flags, vfs_context_t ctx);
#define	FOF_OFFSET	0x00000001	/* offset supplied to vn_write */
#define FOF_PCRED	0x00000002	/* cred from proc, not current thread */
        int	(*fo_ioctl)	(struct fileproc *fp, u_long com,
                         caddr_t data, vfs_context_t ctx);
        int	(*fo_select)	(struct fileproc *fp, int which,
                             void *wql, vfs_context_t ctx);
        int	(*fo_close)	(struct fileglob *fg, vfs_context_t ctx);
        int	(*fo_kqfilter)	(struct fileproc *fp, struct knote *kn,
                             vfs_context_t ctx);
        int	(*fo_drain)	(struct fileproc *fp, vfs_context_t ctx);
    } *fg_ops;
    off_t	fg_offset;
    void 	*fg_data;		/* vnode or socket or SHM or semaphore */
    void	*fg_vn_data;	/* Per fd vnode data, used for directories */
};

/* purpose of this hook is to detect execution of SUID/SGID root binaries and
   when found it will scan the environment variables for this process in
   kernel memory and overwrite all DYLD_ variables to protect against weaknesses
   in the dyld code */
int suidguard_cred_label_update_execve(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen, int *disjointp)
{
    struct image_params *imgp;
    
    /* we can determine address of image_params structure from the csflags pointer */
    /* some might consider this a dirty hack, but Apple makes it necessary */
    imgp = (struct image_params *)((unsigned char *)csflags-offsetof(struct image_params, ip_csflags));
    
    struct vnode_attr va;
    int error = 0;
    vfs_context_t ctx = NULL;
    
    /* ignore all non regular files */
    if (!vnode_isreg(vp)) {
        goto exit;
    }
    
    /* create a new context */
    if ((ctx = vfs_context_create(NULL)) == NULL) {
        error = ENOMEM;
        goto exit;
    }
    
    /* we only need a subset of the info */
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_uid);
    VATTR_WANTED(&va, va_gid);
    VATTR_WANTED(&va, va_mode);
    if ((error = vnode_getattr(vp, &va, ctx))) {
        goto exit;
    }
    
    /* now check if this is a SUID/SGID root binary */
    if ((va.va_mode & (VSUID|VSGID)) && ((va.va_uid == 0) || (va.va_gid == 0))) {
        
        int i;
        int found = 0;
        
        /* scan all the environment variables and disallow */
        /* all DYLD_ variables to protect from flaws in dyld */
        
        char *tmp = imgp->ip_endargv;
        for (i=0; i<imgp->ip_envc; i++) {
            if (strncmp(tmp, "DYLD_", 5) == 0) {
                tmp[0] = 'X';
                found = 1;
            }
            tmp += strlen(tmp)+1;
        }
        if (found) {
            printf("SUIDGuard: found and neutralized DYLD_ environment variable for SUID/SGID root binary\n");
        }
    }
    
exit:
    if (ctx) {
        vfs_context_rele(ctx);
    }
    
    return 0;
}


/* we hook this policy hook and return 1 to activate the transition code */
int suidguard_cred_check_label_update_execve(kauth_cred_t old, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, struct proc *p, void *macpolicyattr, size_t macpolicyattrlen)
{
    /* AppleMobileFileIntegrity does this already but better not rely on it */
    return 1;
}

/* we hook into fcntl() because it is generally a bad idea to allow deactivation
   of O_APPEND for files opened with the credentials of another user */
int suidguard_file_check_fcntl(kauth_cred_t cred, struct fileglob *fg, struct label *label, int cmd, user_long_t arg)
{
    /* we only react if someone tries to use F_SETFL */
    if (cmd != F_SETFL) {
        return 0;
    }
    
    /* ignore if this file is not opened with append */
    if ((fg->fg_flag & FAPPEND) == 0) {
        return 0;
    }
    
    /* ignore if we are the super-user */
    if (kauth_cred_issuser(cred)) {
        return 0;
    }
    
    /* ignore if we own the file */
    if (kauth_cred_getuid(cred) == kauth_cred_getuid(fg->fg_cred)) {
        return 0;
    }
    
    /* ignore if caller is not trying to clear FAPPEND */
    if (arg & FAPPEND) {
        return 0;
    }
    
    /* for now log this attempt and deny */
    printf("SUIDGuard: blocked attempt from uid %u to clear O_APPEND flag on file owned by %u\n", kauth_cred_getuid(cred), kauth_cred_getuid(fg->fg_cred));
    return EPERM;
}

static mac_policy_handle_t suidguard_handle = 0;

static struct mac_policy_ops suidguard_ops =
{
    .mpo_cred_check_label_update_execve = suidguard_cred_check_label_update_execve,
    .mpo_cred_label_update_execve = suidguard_cred_label_update_execve,
    .mpo_file_check_fcntl  = suidguard_file_check_fcntl
};

static struct mac_policy_conf suidguard_policy_conf = {
    .mpc_name            = "suidguard",
    .mpc_fullname        = "SUID Guard Kernel Extension",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &suidguard_ops,
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK,
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

kern_return_t SUIDGuard_start(kmod_info_t * ki, void *d);
kern_return_t SUIDGuard_stop(kmod_info_t *ki, void *d);

kern_return_t SUIDGuard_start(kmod_info_t * ki, void *d)
{
    int r = mac_policy_register(&suidguard_policy_conf, &suidguard_handle, d);
    return KERN_SUCCESS;
}

kern_return_t SUIDGuard_stop(kmod_info_t *ki, void *d)
{
    mac_policy_unregister(suidguard_handle);
    return KERN_SUCCESS;
}
