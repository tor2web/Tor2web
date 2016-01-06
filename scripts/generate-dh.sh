# Generate SSL DH automatically
SSLDH=`grep ^ssl_dh /etc/tor2web.conf 2>/dev/null | awk '{ print $3 }'`
if (test $SSLDH); then
                        if (test -f $SSLDH); then
                                exit 0
                        else
                                openssl dhparam -out $SSLDH 2048 &
                        fi
 else
                        if (test -f /home/tor2web/certs/tor2web-dh.pem); then
                                exit 0
                        else
                                openssl dhparam -out /home/tor2web/certs/tor2web-dh.pem 2048 &
                        fi

fi
