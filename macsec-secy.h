#ifndef __MACSEC_SECY_H__
#define __MACSEC_SECY_H__

#define MACSEC_SECY_NAMELEN 16

enum macsec_secy_mode {
    MACSEC_SECY_PASS = 0,   /* every packet is transmitted (default) */
    MACSEC_SECY_PERCENT,    /* pass some percent of the packets */
    MACSEC_SECY_TIME,       /* work (and fail) on a timely basis */
};

struct macsec_secy_userinfo {
    char name[MACSEC_SECY_NAMELEN];
    int mode;
    int arg1;
    int arg2;
};

/* Following are the ioctl commands needed to interact with macsec-secy interface */
#define SIOCMACSECSECYSETINFO SIOCDEVPRIVATE
#define SIOCMACSECSECYGETINFO (SIOCDEVPRIVATE+1)

#endif /* __MACSEC_SECY_H__ */
