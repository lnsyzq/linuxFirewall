#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetFilterHook;

unsigned int telnetFilter(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  char src_ip[16];
  char dst_ip[16];
  
  //source
  snprintf(src_ip, 16, "%pI4", &iph->saddr);
  //destination
  snprintf(dst_ip, 16, "%pI4", &iph->daddr);

  //rule 1: dst ip address "10.0.2.7" and port number"23"
  //disable the telnet to machine b
  if (iph->protocol == IPPROTO_TCP && (strcmp(dst_ip, "10.0.2.7") == 0) && tcph->dest == htons(23)) {
    printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  }
  
  //rule2: source ip address "10.0.2.7"
  //disable the telent from machine b to machie a
  if (iph->protocol == IPPROTO_TCP && (strcmp(src_ip, "10.0.2.7") == 0) && tcph->dest == htons(23)) {
    printk(KERN_INFO "Dropping telnet packet from %d.%d.%d.%d\n",
        ((unsigned char *)&iph->saddr)[0],
        ((unsigned char *)&iph->saddr)[1],
        ((unsigned char *)&iph->saddr)[2],
        ((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;
  }
  
  //rule3: disable web service:
  if (iph->protocol == IPPROTO_TCP && (strcmp(dst_ip, "64.35.176.173") == 0) && tcph->dest == htons(80)) {    
    printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;    
  } else {
    return NF_ACCEPT;
  }
}


int setUpFilter(void) {
        printk(KERN_INFO "Registering a Telnet filter.\n");
        telnetFilterHook.hook = telnetFilter;
        telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
	//telnetFilterHook.hooknum = NF_INET_LOCAL_IN;
        telnetFilterHook.pf = PF_INET;
        telnetFilterHook.priority = NF_IP_PRI_FIRST;

        // Register the hook.
        nf_register_hook(&telnetFilterHook);
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Telnet filter is being removed.\n");
        nf_unregister_hook(&telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");



