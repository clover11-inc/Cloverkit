#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi


if [ "${BH_LCD_MODE:-cli}" = "graphical" ]; then
    exec /usr/local/bin/ethernet-live eth0
fi

/usr/local/bin/eth-info 2>/dev/null |
awk '
/^Interface :/ {iface=$3}
/^Link      :/ {link=$3}
/^Speed     :/ {
    speed=$3
    duplex=$4
}
/^IP        :/ {ip=$3}
/^Name      :/ {name=$3}
/^Port      :/ {
    $1=""
    $2=""
    sub(/^[ \t]+/,"")
    port=$0
}
/^VLAN      :/ {vlan=$3}

END {
    print "ETHERNET"

    if(iface!="")
        print iface "  " link

    if(speed!="")
        print speed " " duplex

    if(ip!="")
        print ip

    if(name!="") {
        print ""
        print name

        if(port!="")
            print port

        if(vlan!="")
            print "VLAN " vlan
    }
}
'
