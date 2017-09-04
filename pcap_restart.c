#include "header1.h"
char *detect_c[] = {"Host: test.gilgil.net","Host: hitomi.la","Host: kass.org.kp","Host: kcna.kp","Host: kitribob.wiki","Host: ks8282.com","Host: linoit.comusersmen1212canvases19%EA%B8%88%20","Host: naevr.com","Host: named.comgameladderv2_index.php","Host: naver6.com","Host: avnana.com","Host: pornpros.com","Host: rodong.rep.kp","Host: snoopspy.comdownload","Host: test.gilgil.netstreamingtest.mp4","Host: uriminzokkiri.com","Host: 4shared.com","Host: bamwar25.com","Host: faa25.com","Host: ilbe.com/ilbe","Host: kimmadam.net","Host: minjok.com","Host: narutoxxx.com","Host: naver.cm","Host: ryomyong.com","Host: sedisk.com","Host: sk386.com","Host: tcosc.net","Host: torenzoa.net","Host: umj262.com","Host: uriminzokkiri.com","Host: winclub88.net"};
int check_data(unsigned char * data)
{
    struct sniff_ip *ip;
    uint16_t size_ip;
    ip = (struct sniff_ip*)(data);
    size_ip = IP_HL(ip)*4;
    if(ip->ip_p==0x6){
        struct sniff_tcp *tcp;
        tcp = (struct sniff_tcp*)(data + size_ip);
        uint16_t size_tcp;
        size_tcp = TH_OFF(tcp)*4;
        char *payload;
        payload = (char *)(data + size_ip + size_tcp);
        for(int i=0; i < 32 ; i++){
        if(strstr(payload,detect_c[i]) != NULL){
            return 2;
        }
    }
    }
    return 1;
}
