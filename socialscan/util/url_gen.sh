#!/bin/bash
urlroot="http://malwarerepo.trustproxy.org/contents/"

#/usr/bin/mysql -u root -pb12kj3as201n socialscan -sN -e 'select url,scannervv from scans where malicious=1 order by rand()' | awk 'NR > 1 {if (avc[$2] < 20) {urls[$2] = urls[$2]^C1 "\n" ; avc[$2] = avc[$2] + 1}} END {for (i in urls) {print urls[i] >> "av_lists/"i}}' 

/usr/bin/mysql -u root -pb12kj3as201n socialscan -sN -e 'SELECT DISTINCT(url),malicious FROM scans ORDER BY rand()' | awk -v bnum=$(($1-1)) '($2 == 0 && bcount <= bnum) {print $1; bcount++} $2 == 1 {print $1}' > $2

remlines=$((1000-`wc -l $2 | cut -d ' ' -f 1`))

ls /home/malwarerepo/malwarerepo.trustproxy.org/contents | awk -v urlroot=$urlroot 'NR%(int(1+NR/750)) == 0 {print urlroot $0}' | shuf | head -n $remlines >> $2

chown malwarerepo:malwarerepo $2
