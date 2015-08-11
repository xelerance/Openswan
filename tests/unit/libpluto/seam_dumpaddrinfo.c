void dump_addr_info(struct addrinfo *ans)
{
    unsigned int ansnum = 0;
    while(ans) {
        char addrbuf[ADDRTOT_BUF];
        printf("ans %03u canonname=%s protocol=%u family=%u len=%u\n"
               , ansnum, ans->ai_canonname, ans->ai_protocol, ans->ai_family, ans->ai_addrlen);
        if(ans->ai_addrlen && ans->ai_addr) {
            sin_addrtot(ans->ai_addr, 0, addrbuf, sizeof(addrbuf));
            printf("        result=%s\n", addrbuf);
        }

        ans = ans->ai_next;
        ansnum++;
    }
}
