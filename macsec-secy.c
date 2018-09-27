/* 	macsec-secy.c: 
        An off-the-shelf psuedo net driver for providing macsec secy support for an macsec-enabled actual device
	in Linux environment.

	The purpose of this driver is to provide a pseudo device that sits above the actual device when macsec is activated 
	on actual device and takes care of encryption/decryption of packets based on keys and algorithm suite downloaded by user space.

	This was written by looking at dummy driver, vlan and the ieee802.11 implementations in linux kernel.

	Initial Commit: Samsung Research India, Bangalore. 08th July 2015
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <net/rtnetlink.h>
#include <linux/if_arp.h>

/* Crypto Stuff */
#include <linux/crypto.h>
#include <crypto/aead.h>

/* Private headers */
#include "macsec-secy.h"

#define MACSECM_HDR_LEN_WITHOUT_SCI (8)
#define MACSECM_HDR_LEN_WITH_SCI (MACSECM_HDR_LEN_WITHOUT_SCI + 4 /* For Encoding SCI */)
#define MACSEC_ETH_TYPE 0x88E5

#define MACSEC_GCM_AES_128_ICV_LEN 16

/*
 * --------------------------------------------------------------------------------------------------*
 * definition of the "private" data structure used by this pseudo interface
 * Should hold algorithm suite used for protecting/authentication the traffic along with relevent keys
 *
 * --------------------------------------------------------------------------------------------------*
 */
struct macsec_secy_private {
    struct net_device_stats priv_stats;
    struct net_device *priv_device; /* interface used to xmit data */
    int priv_mode; /* how to drop packets */
    int priv_arg1; /* arguments to the dropping mode */
    int priv_arg2;
    struct crypto_aead* tfm;
};

/* Crypto Stuff : Move this to a different file later */
struct macsec_algo_aead {
	char		alg_name[64];
	unsigned int	alg_key_len;	/* in bits */
	unsigned int	alg_icv_len;	/* in bits */
	char		alg_key[0];
};

/* SecTag Stuff */
struct macsec_hdr_sci {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 v:1,
	es:1,
	sc:1,
	scb:1,
	e:1,
	c:1,
	an:2;
#endif
	u8	h_macsec_sl;
	__be32	h_macsec_pn;
	__be32  h_macsec_sci;
};

struct macsec_hdr {
#if 0
	struct {
		unsigned char	h_dest[ETH_ALEN];
		unsigned char	h_source[ETH_ALEN];
		__be16		h_vlan_proto;
	}mac_ethhdr;
#endif
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 an:2,
	c:1,
	e:1,
	scb:1,
	sc:1,
	es:1,
	v:1;
#endif
	__u8	h_macsec_sl;
//	__be32	h_macsec_pn;
};

struct macsec_skb_cb {
	void *tmp;
};

#define MACSEC_SKB_CB(__skb) ((struct macsec_skb_cb *)&((__skb)->cb[0]))

static int nummacsecys = 1;

static struct net_device *macsec_secy_dev; /* forward decl */


/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
};

static struct rtnl_link_stats64 *macsec_secy_get_stats64(struct net_device *dev,
						   struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_dstats *dstats;
		u64 tbytes, tpackets;
		unsigned int start;

		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
		} while (u64_stats_fetch_retry_irq(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
	}
	return stats;
}

static int macsec_secy_dev_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

	return 0;
}

static void macsec_secy_dev_uninit(struct net_device *dev)
{
	struct macsec_secy_private *priv = netdev_priv(dev);
	free_percpu(dev->dstats);
	netdev_rx_handler_unregister(priv->priv_device);
}

static int macsec_secy_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

/*
 * Allocate an AEAD request structure with extra space for SG and IV.
 *
 * For alignment considerations the IV is placed at the front, followed
 * by the request and finally the SG list.
 *
 * TODO: Use spare space in skb for this where possible.
 */
#if 0
static void *macsec_alloc_tmp(struct crypto_aead *aead, int nfrags)
{
	unsigned int len = 0;

	len += crypto_aead_ivsize(aead);

	if (len) {
		len += crypto_aead_alignmask(aead) &
		       ~(crypto_tfm_ctx_alignment() - 1);
		len = ALIGN(len, crypto_tfm_ctx_alignment());
	}

	len += crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));

	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}
#endif

static void macsec_secy_output_done(struct crypto_async_request *base, int err)
{
    //struct sk_buff *skb = base->data;

    //kfree(MACSEC_SKB_CB(skb)->tmp);
    //pr_info("%s(%d): After Encryption head = %d, data = %d, total = %d\n", __FUNCTION__, __LINE__, skb->len - skb->data_len, skb->data_len, skb->len);
    pr_info("%s(%d): %d\n", __FUNCTION__, __LINE__, err);

    /* TODO: Schedule this packet for transmission to ethernet device */

    return;

}

int macsec_secy_hard_header(struct sk_buff *skb, struct net_device *dev, 
        unsigned short type, const void *daddr, const void *saddr, unsigned len)
{
    struct macsec_secy_private *priv;
    int retval;


    priv = netdev_priv(dev);
    /* TODO: Check whether protocol type be changed to MACSEC during HEADER construction or while transmiting */
    //skb->protocol = MACSEC_ETH_TYPE;
    //type = MACSEC_ETH_TYPE;

    /* Assign the actual device to SKB so that MAC of actual device is used during as SRC address during MAC header construction */
    skb->dev = priv->priv_device; 
    saddr = skb->dev->dev_addr;
    retval = skb->dev->header_ops->create(skb, skb->dev, type, daddr, saddr, len);

    skb->dev = dev; /* Re-assign the psuedo device to skb */

    return retval;
}

static int macsec_secy_rebuild_header(struct sk_buff *skb)
{
    struct macsec_secy_private *priv = (struct macsec_secy_private *)netdev_priv((const struct net_device*)macsec_secy_dev);
    int retval;

    if(priv == NULL){
	pr_err("%s(%d): Private Data is Null\n", __FUNCTION__, __LINE__);
	/* TODO: Use Standard Error codes */
	return -1;
    }

    skb->dev = priv->priv_device;
    retval = skb->dev->header_ops->rebuild(skb);
    skb->dev = macsec_secy_dev;
    return retval;
}

struct header_ops macsec_secy_header_ops = 
{
	.create = macsec_secy_hard_header,
	.rebuild = macsec_secy_rebuild_header,
	.parse = eth_header_parse,
	.cache = NULL,
	.cache_update = NULL,
};

/* --------------------------------------------------------------------------
 * open and close
 */
int macsec_secy_open(struct net_device *dev)
{
    /* TODO: Explore this */
    /* mark the device as operational */
    //dev->start = 1;
    //dev->tbusy = 0;
    //MOD_INC_USE_COUNT;
    return 0;
}
int macsec_secy_close(struct net_device *dev)
{
    /* TODO: Explore this */
    //dev->start = 0;
    //dev->tbusy = 1;
    //MOD_DEC_USE_COUNT;
    return 0;
}

/* --------------------------------------------------------------------------
 * get_stats: return a pointer to the device statistics
 */
struct net_device_stats *macsec_secy_get_stats(struct net_device *dev)
{
    return &((struct macsec_secy_private *)(netdev_priv(dev)))->priv_stats;
}

static inline struct macsec_hdr* mac_hdr(const struct sk_buff *skb)
{
    return (struct macsec_hdr  *)skb_network_header(skb);
}

static int macsec_aes_gcm_encrypt(struct crypto_aead *tfm, u8 *iv, u8 *aad, u8 aad_len,
			       u8 *data, size_t data_len, u8 *icv)
{
	struct scatterlist assoc, pt, ct[2];
        int ret = 0;

	struct aead_request *aead_req;
	aead_req = aead_request_alloc(tfm, GFP_KERNEL);

	sg_init_one(&pt, data, data_len);
	sg_init_one(&assoc, aad, aad_len);
	sg_init_table(ct, 2);
	sg_set_buf(&ct[0], data, data_len);
	sg_set_buf(&ct[1], icv, MACSEC_GCM_AES_128_ICV_LEN);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_assoc(aead_req, &assoc, assoc.length);
	aead_request_set_crypt(aead_req, &pt, ct, data_len, iv);

	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG, macsec_secy_output_done, NULL);
	ret = crypto_aead_encrypt(aead_req);
	return ret;
}

/* --------------------------------------------------------------------------
 * xmit: actual delivery (or not) of the data packets
 */
int macsec_secy_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int err;
    struct macsec_secy_private *priv = netdev_priv(dev);
    int accept; /* accept this packet or drop it */
    static unsigned long randval;

    struct ethhdr *ethhdr;
    int proto;

    struct macsec_hdr *pmacsec;

    unsigned int pn = 0;
    unsigned int alen = 0; /* Authentication Data len of the txfrm. ICV lenght of MACSEC should be same as this */
    unsigned int blksize = 0;
    unsigned int clen = 0;
    int assoclen;
    int plen = 0;
    void *tmp = NULL;
    char *icv;

    struct crypto_aead *aead;

    /*TODO: Obtain it from device's private configuration which should store the suite used and kesys received from user space.*/
    char iv_data[20]  = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88";
    char assoc_data[20] = "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2";

    int encrypt_len;
    priv = netdev_priv(dev);

    aead = priv->tfm;
    alen = crypto_aead_authsize(aead);

    ethhdr = (struct ethhdr *)skb->data;

    proto = ntohs(ethhdr->h_proto);

    pr_info("%s(%d): Offset b/w Mac and Network Headers = %d\n", __FUNCTION__, __LINE__, skb_mac_header(skb)-skb_network_header(skb));

    blksize = ALIGN(crypto_aead_blocksize(aead), 4);
    clen = ALIGN(skb->len - sizeof(struct ethhdr), blksize);
    plen = clen - (skb->len - sizeof(struct ethhdr));

    encrypt_len = skb->len - (sizeof(struct ethhdr) - 2);

    pr_info("%s(%d): Encrypt Len = %d\n", __FUNCTION__, __LINE__, encrypt_len);

    assoclen = MACSECM_HDR_LEN_WITHOUT_SCI + sizeof(struct ethhdr);

    pr_info("%s(%d): Tail Room is %d, Head Room is %d\n", __FUNCTION__, __LINE__, skb_tailroom(skb), skb_headroom(skb));

    if (WARN_ON(skb_tailroom(skb) <  MACSEC_GCM_AES_128_ICV_LEN ||
	    skb_headroom(skb) < MACSECM_HDR_LEN_WITHOUT_SCI)) {
	pr_warn("%s(%d): Tail Room is %d, Head Room is %d\n", __FUNCTION__, __LINE__, skb_tailroom(skb), skb_headroom(skb));
	/* TODO : Use appropriate MACRO */
	return -1;
    }

    pmacsec = (struct macsec_hdr *)skb_push(skb, MACSECM_HDR_LEN_WITHOUT_SCI);

    if (pmacsec == NULL) {
	pr_err("%s(%d): Failed to append macsec header\n",__FUNCTION__, __LINE__);
	return -ENOMEM;
    }

     /* Move the mac addresses to the beginning of the new header. */
    memmove(skb->data, skb->data + MACSECM_HDR_LEN_WITHOUT_SCI, 2 * ETH_ALEN /*+ 2*//*Eth header*/);
    skb_reset_mac_header(skb);


    pr_info("%s(%d):  Offset b/w Mac and Network Headers post Sectagging %d\n", __FUNCTION__, __LINE__, skb_mac_header(skb)-skb_network_header(skb));

    skb_set_network_header(skb, skb_network_offset(skb) - 2);

    ethhdr = (struct ethhdr *)skb_mac_header(skb);
    ethhdr->h_proto =  htons(MACSEC_ETH_TYPE);
    skb->protocol = MACSEC_ETH_TYPE;

    pmacsec = (struct macsec_hdr *)((char*)pmacsec + sizeof(struct ethhdr));
    /* TODO: Update SecTag based on the configuration present in private info of this pseudo device */
    pmacsec->v = 0;
    pmacsec->es = 1;
    pmacsec->sc = 0;
    pmacsec->scb = 0;
    pmacsec->e = 1;
    pmacsec->c = 1;
    pmacsec->an = 2;

    pmacsec->h_macsec_sl = 0x00;
    pmacsec = (struct macsec_hdr *)((char*)pmacsec + sizeof(*pmacsec));
    pn = 0x11223344;
    memcpy(pmacsec, &pn, sizeof(pn));

   MACSEC_SKB_CB(skb)->tmp = tmp;

   icv = skb_put(skb, MACSEC_GCM_AES_128_ICV_LEN);

   if ((unsigned char*)pmacsec+sizeof(pn) == skb_network_header(skb)) {
	pr_warn("%s(%d): SKB network header is aligned\n", __FUNCTION__, __LINE__);
   }

   err = macsec_aes_gcm_encrypt(aead, iv_data, assoc_data, 20,
			       (unsigned char*)skb_network_header(skb) , encrypt_len, icv);
   pr_info("%s(%d): Encryption Output = %d\n", __FUNCTION__, __LINE__, err);
   if (err == -EINPROGRESS)
	goto error;

   if (err == -EBUSY)
	err = NET_XMIT_DROP;

   /* TODO: Take care of freeing */
   //kfree(tmp);

    if (!priv->priv_device) { /* cannot send to anyone, just return */
	priv->priv_stats.tx_errors++;
	priv->priv_stats.tx_dropped++;
	return 0;
    }

    switch (priv->priv_mode) {	
        case MACSEC_SECY_PERCENT:
	    if (!randval) randval = jiffies; /* a typical seed */
	    /* hash the value, according to the TYPE_0 rule of glibc */
	    randval = ((randval * 1103515245) + 12345) & 0x7fffffff;
	    accept = (randval % 100) < priv->priv_arg1;
	    break;

        case MACSEC_SECY_TIME:
	    randval = jiffies % (priv->priv_arg1 + priv->priv_arg2);
	    accept = randval < priv->priv_arg1;
	    break;
	    
        case MACSEC_SECY_PASS:
        default: /* unknown mode: default to pass */
	    accept = 1;
    }
	    
    if (!accept) {
	priv->priv_stats.tx_errors++;
	priv->priv_stats.tx_dropped++;
	return 0;
    }
    /* else, pass it to the real interface */

    priv->priv_stats.tx_packets++;
    priv->priv_stats.tx_bytes += skb->len;

    skb->dev = priv->priv_device;
    skb->priority = 1;
    err = dev_queue_xmit (skb);
    /* TODO: Use appropriate MACRO */
    return 0;


error:
    pr_err("%s(%d): Error\n", __FUNCTION__, __LINE__);
    /*TODO: Decide what needs to be done */
    return NETDEV_TX_OK;

}

/* --------------------------------------------------------------------------
 * ioctl: let user programs configure this interface
 */
int macsec_secy_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    int err;
    struct net_device *slave;
    struct macsec_secy_private *priv = netdev_priv(dev);
    /* hold a local (kernel-space) copy of the configuration data */
    struct macsec_secy_userinfo info;
    /* and a pointer into user space as well */
    struct macsec_secy_userinfo *uptr = (struct macsec_secy_userinfo *)ifr->ifr_data;


    /* only authorized users can control the interface */
    if (cmd == SIOCMACSECSECYSETINFO && !capable(CAP_NET_ADMIN))
	return -EPERM;
    
    /* process the command */
    switch(cmd) {
        case SIOCMACSECSECYGETINFO: /* return configuration to user space */

	    /* interface name */
	    memset(info.name, 0, MACSEC_SECY_NAMELEN);
	    if (priv->priv_device)
		strncpy(info.name, priv->priv_device->name, MACSEC_SECY_NAMELEN-1);
	    
	    /* parameters */
	    info.mode = priv->priv_mode;
	    info.arg1 = priv->priv_arg1;
	    info.arg2 = priv->priv_arg2;

	    /* return the data structure to  user space */
	    err = copy_to_user(uptr, &info, sizeof(info));
	    if (err) return err;
	    break;

        case SIOCMACSECSECYSETINFO:
	    /* retrieve the data structure from user space */
	    err = copy_from_user(&info, uptr, sizeof(info));
	    if (err) return err;

	    pr_info("name: %s, arg %i %i\n", info.name, info.arg1, info.arg2);

	    /* interface name */
	    slave = __dev_get_by_name(dev_net(dev), info.name);
	    if (!slave)
		return -ENODEV;
	    if (slave->type != ARPHRD_ETHER && slave->type != ARPHRD_LOOPBACK)
		return -EINVAL;

	    /* The interface is good, get hold of it */
	    priv->priv_device = slave;

	    if (slave->header_ops->create && slave->header_ops->rebuild) {
		dev->header_ops = &macsec_secy_header_ops;
	    }

	    /* also, and clone its IP, MAC and other information */
	    memcpy(dev->dev_addr,  slave->dev_addr,  (unsigned int)sizeof(slave->dev_addr));
	    memcpy(dev->broadcast, slave->broadcast, (unsigned int)sizeof(slave->broadcast));

	    /* accept the parameters (no checks here) */
	    priv->priv_mode = info.mode;
	    priv->priv_arg1 = info.arg1;
	    priv->priv_arg2 = info.arg2;

	    break;
	/*TODO: Set crypto keys by defining new cryto option */

        default:
	    return -EOPNOTSUPP;
    }
    return 0;
}

/* TODO: Neighbour setup. May be required for ARP/ND */
#if 0
int macsec_secy_neigh_setup(struct neighbour *n)
{
    if (n->nud_state == NUD_NONE) {
	n->ops = &arp_broken_ops;
	n->output = n->ops->output;
    }
    return 0;
}

int macsec_secy_neigh_setup_dev(struct net_device *dev, struct neigh_parms *p)
{
    if (p->tbl->family == AF_INET) {
	p->neigh_setup = macsec_secy_neigh_setup;
	p->ucast_probes = 0;
	p->mcast_probes = 0;
    }
    return 0;
}
#endif

static int macsec_secy_neigh_setup_dev(struct net_device *dev, struct neigh_parms *pa)
{
        struct macsec_secy_private *dev_priv  = (struct macsec_secy_private*)netdev_priv(dev);
	struct net_device *real_dev = NULL;
        const struct net_device_ops *ops = NULL;
        int err = 0;

	real_dev = dev_priv->priv_device;
	if(real_dev == NULL) {
		return err;
	}

	ops = real_dev->netdev_ops;

	if (!ops) {
		return err;
	}

	if (!ops->ndo_neigh_setup){
		return err;
	}

        if (netif_device_present(real_dev) && ops->ndo_neigh_setup) {
                err = ops->ndo_neigh_setup(real_dev, pa);
	}

        return err;
}

static const struct net_device_ops macsec_secy_netdev_ops = {
	.ndo_open		= macsec_secy_open,
	.ndo_stop		= macsec_secy_close,
	.ndo_init		= macsec_secy_dev_init,
	.ndo_uninit		= macsec_secy_dev_uninit,
	.ndo_start_xmit		= macsec_secy_xmit,
        .ndo_do_ioctl           = macsec_secy_ioctl,
	.ndo_get_stats		= macsec_secy_get_stats,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= macsec_secy_get_stats64,
	.ndo_change_carrier	= macsec_secy_change_carrier,
	.ndo_neigh_setup	= macsec_secy_neigh_setup_dev
};


int macsec_aes_gcm_decrypt(struct crypto_aead *tfm, u8 *j_0, u8 *aad, u8 aad_len,
			      u8 *data, size_t data_len, u8 *mic)
{
	struct scatterlist assoc, pt, ct[2];
	int err;

	struct aead_request *aead_req;
	aead_req = aead_request_alloc(tfm, GFP_KERNEL);

	if (data_len == 0)
		return -EINVAL;

	sg_init_one(&pt, data, data_len);
	sg_init_one(&assoc, aad, aad_len);
	sg_init_table(ct, 2);
	sg_set_buf(&ct[0], data, data_len);
	sg_set_buf(&ct[1], mic, MACSEC_GCM_AES_128_ICV_LEN);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_assoc(aead_req, &assoc, assoc.length);
	aead_request_set_crypt(aead_req, ct, &pt,
			       data_len + MACSEC_GCM_AES_128_ICV_LEN, j_0);

	err = crypto_aead_decrypt(aead_req);
	return  err;
}

rx_handler_result_t macsec_crypto_gcmp_decrypt(struct sk_buff *skb)
{
	struct ethhdr *hdr;
        int decrypt_len;
	struct crypto_aead *aead;
	struct macsec_secy_private *priv;
	/*TODO: Obtain it from device's private configuration which should store the suite used and kesys received from user space.*/
        char iv_data[200]  = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88";
        char assoc_data[200] = "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2";

	priv = netdev_priv(macsec_secy_dev);
	aead = priv->tfm;

	decrypt_len = skb->len - (MACSECM_HDR_LEN_WITHOUT_SCI + MACSEC_GCM_AES_128_ICV_LEN) + 2;

	if (decrypt_len < 0)
		return RX_HANDLER_ANOTHER;
#if 0
	/* TODO: Is it Required ?. Might be required if packets are fragmented */
	if (!pskb_may_pull(skb, sizeof(struct ethhdr) + MACSECM_HDR_LEN_WITHOUT_SCI)) {
		pr_err("%s(%d): SKB Pull failed\n", __FUNCTION__, __LINE__);
		return RX_HANDLER_ANOTHER;
	}
#endif

	/* TODO: Do this After decryption */
	if (skb_linearize(skb))
		return RX_HANDLER_ANOTHER;

	if (macsec_aes_gcm_decrypt(aead, iv_data, assoc_data, 20,
			    skb->data + MACSECM_HDR_LEN_WITHOUT_SCI - 2,
			    decrypt_len,
			    (skb->data + skb->len -  MACSEC_GCM_AES_128_ICV_LEN))) {
		return RX_HANDLER_ANOTHER;
	}

	hdr = (struct ethhdr*)skb_mac_header(skb);
	memcpy((char*)&hdr->h_proto, (skb->data + MACSECM_HDR_LEN_WITHOUT_SCI - 2), 2);
	skb->protocol = (*((unsigned short*)(skb->data + MACSECM_HDR_LEN_WITHOUT_SCI - 2)));

	/* Remove Macsec header */
	if (pskb_trim(skb, skb->len - MACSEC_GCM_AES_128_ICV_LEN))
		return RX_HANDLER_ANOTHER;
        /* TODO: Take care if SCI is encoded */
	//memmove(skb->data + MACSECM_HDR_LEN_WITHOUT_SCI, skb->data, 0);

	skb_set_network_header(skb, MACSECM_HDR_LEN_WITHOUT_SCI);
	skb_pull(skb, MACSECM_HDR_LEN_WITHOUT_SCI);

	skb_mac_header_rebuild(skb);
	return RX_HANDLER_ANOTHER;
}

/* Called with rcu_read_lock and bottom-halves disabled. */
static rx_handler_result_t macsec_netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct ethhdr *ethhdr;
	struct net_device *orig_dev;
	int err = RX_HANDLER_PASS;

	orig_dev = skb->dev;

	if (skb == NULL) {
		pr_err("%s(%d): skb is null\n", __FUNCTION__, __LINE__);
		return RX_HANDLER_PASS;
	}

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	ethhdr = (struct ethhdr *)skb_mac_header(skb);

    	if (ethhdr) {
		if (ethhdr->h_proto == htons(MACSEC_ETH_TYPE)) {
			err = macsec_crypto_gcmp_decrypt(skb);
			skb->dev = macsec_secy_dev; /* TODO: Should it be used? Yes. but might be tweaked later */
			if (unlikely(skb->pkt_type == PACKET_OTHERHOST)) {
				skb->pkt_type = PACKET_HOST;
			}
		}

	}
	return err;
}

static struct crypto_aead * macsec_aead_init(const char *driver, u32 type, u32 mask)
{
	struct crypto_aead *tfm;
	//int err = 0;

	tfm = crypto_alloc_aead(driver, type, mask);

	if (IS_ERR(tfm)) {
		pr_err("alg: aead: Failed to load transform for %s: "
		       "%ld\n", driver, PTR_ERR(tfm));
		return NULL;
	}
	return tfm;
}

static void macsec_secy_setup(struct net_device *dev)
{
	struct macsec_secy_private *priv;
	struct net_device *slave;
	int err;

        char key[20] = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
	/*
	* fill the fields of the device structure that are used
	*/

	priv = netdev_priv(dev);

	if (!priv) {
		pr_err("%s(%d): Private Data is not allocated\n", __FUNCTION__, __LINE__);
		return;
	}

	ether_setup(dev);

	dev->needed_headroom = ETH_HLEN + MACSECM_HDR_LEN_WITH_SCI;
        dev->needed_tailroom = 128 + 128; /* TODO: use MACRO */

	/* interface name */
	/* TODO: Configure it based on information received from user space. */
	slave = __dev_get_by_name(dev_net(dev), "eth0");
	if (!slave) {
		pr_err("%s(%d): Obtained Device node for eth0 interface\n", __FUNCTION__, __LINE__);
		return ;
	}
	if (slave->type != ARPHRD_ETHER && slave->type != ARPHRD_LOOPBACK) {
		pr_err("%s(%d): Eth0 is neither of type ETHER nor LOOPBACK\n", __FUNCTION__, __LINE__);	
		return ;
	}

	/* The interface is good, get hold of it */
	priv->priv_device = slave;

	/* Initialize the device structure. */
	dev->netdev_ops = &macsec_secy_netdev_ops;
        dev->header_ops = &macsec_secy_header_ops;
	dev->hard_header_len = slave->hard_header_len;

	dev->destructor = free_netdev;

	/* TODO: Decided on RTNL locks */
	//rtnl_lock();
	err = netdev_rx_handler_register(slave, macsec_netdev_frame_hook, NULL);
	if (err) {
		pr_err("%s(%d): Failed to regsiter netdev rx handler\n", __FUNCTION__, __LINE__);
	}
	//rtnl_unlock();	


	/* Fill in device structure with ethernet-generic values. */
	dev->tx_queue_len = 0;
	//dev->flags |= IFF_NOARP; /* TODO */
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_TSO;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	eth_hw_addr_random(dev);

	/* TODO: Configure it based on information received from user space. */
        priv->tfm = macsec_aead_init("gcm(aes)",3, CRYPTO_ALG_ASYNC);

        err = crypto_aead_setkey(priv->tfm, key,16);
        if (err) {
           pr_err("%s(%d): Error while setting key is %d\n", __FUNCTION__, __LINE__, err);
	   goto error;
        }

        err = crypto_aead_setauthsize(priv->tfm, 16);
        if (err) {
           pr_err("%s(%d): Error while setting auth size is %d\n", __FUNCTION__, __LINE__, err);
	   goto error;
        }

error:
	return;
}

static int macsec_secy_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static struct rtnl_link_ops macsec_secy_link_ops __read_mostly = {
	.kind		= "macsec_secy",
	.setup		= macsec_secy_setup,
	.validate	= macsec_secy_validate,
};

/* Number of Macsec Secy devices to be set up by this module. */
module_param(nummacsecys, int, 0);
MODULE_PARM_DESC(nummacsecys, "Number of macsec secy pseudo devices");

static int __init macsec_secy_init_one(void)
{
	struct net_device *dev_macsec_secy;
	int err = 0;

	/* TODO: Alloc Netdev can either take 4 or 3 parameters based on kernel version */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,55)
	dev_macsec_secy = alloc_netdev(sizeof(struct macsec_secy_private), "macsec_secy%d", /*NET_NAME_UNKNOWN,*/ macsec_secy_setup);
#else
	dev_macsec_secy = alloc_netdev(sizeof(struct macsec_secy_private), "macsec_secy%d", NET_NAME_UNKNOWN, macsec_secy_setup);
#endif
	if (!dev_macsec_secy)
		return -ENOMEM;

	dev_macsec_secy->rtnl_link_ops = &macsec_secy_link_ops;

	err = register_netdevice(dev_macsec_secy);
	if (err < 0)
		goto err;

	macsec_secy_dev = dev_macsec_secy;
	return 0;

err:
	free_netdev(dev_macsec_secy);
	return err;
}

static int __init macsec_secy_init_module(void)
{
	int i, err = 0;

	rtnl_lock();
	err = __rtnl_link_register(&macsec_secy_link_ops);
	if (err < 0)
		goto out;

	for (i = 0; i < nummacsecys && !err; i++) {
		err = macsec_secy_init_one();
		cond_resched();
	}
	if (err < 0)
		__rtnl_link_unregister(&macsec_secy_link_ops);

out:
	rtnl_unlock();

	return err;
}

static void __exit macsec_secy_cleanup_module(void)
{
	rtnl_link_unregister(&macsec_secy_link_ops);
}

module_init(macsec_secy_init_module);
module_exit(macsec_secy_cleanup_module);
MODULE_LICENSE("GPL"); /* TODO: Decide on the License */
MODULE_ALIAS_RTNL_LINK("macsec_secy");
