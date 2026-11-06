FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 tcpdump
COPY firewall/rules.sh /usr/local/bin/rules.sh
RUN sed -i 's/\r$//' /usr/local/bin/rules.sh && chmod +x /usr/local/bin/rules.sh
CMD ["/usr/local/bin/rules.sh"]
