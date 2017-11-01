<?php
echo 'Downloading...';
$file = file_get_contents('https://ftp.apnic.net/stats/apnic/delegated-apnic-latest');
//$file = file_get_contents('delegated-apnic-latest.txt');
echo "Ok!\r\n";
echo 'Explodig to row...';
$file = nl2br($file);
$results = explode('<br />', $file);
echo "Ok!\r\n";
echo 'Analysing:' . "\r\n";
$i = 0;
$windows_add = $windows_del = '';
$android_up = $android_down = "
#!/bin/sh\n
alias nestat=\'/system/xbin/busybox netstat\'\n
alias grep=\'/system/xbin/busybox grep\'\n
alias awk=\'/system/xbin/busybox awk\'\n
alias route=\'/system/xbin/busybox route\'\n
gateway=`netstat -rn | grep ^0\.0\.0\.0 | awk \'{print $2}\'`\n
";
foreach ($results as $row) {
    $params = explode('|', $row);
    if (count($params) != 7 || $params[1] != 'CN') {
        continue;
    }
    //分析是否为获取地址以及掩码
    if (!filter_var($params[3], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        continue;
    }
    $iplong = ip2long($params[3]);
    $hostLong = log($params[4], 2);
    $markLong = 32 - $hostLong;
    $markStr = long2ip(0xffffffff << $hostLong);
    echo $params[3] . ' ' . $markStr . ' ' . $hostLong . ' ' . $markLong . ' ' . "\r\n";
    $windows_add .= 'add ' . $params[3] . ' mask ' . $markStr . ' default METRIC default IF default' . "\n";
    $windows_del .= 'delete ' . $params[3] . ' mask ' . $markStr . ' default METRIC default IF default' . "\n";
    $android_up .= 'route add -net ' . $params[3] . ' netmask ' . $markStr . ' gw $gateway' . "\n";
    $android_down .= 'route del -net ' . $params[3] . ' netmask ' . $markStr . "\n";
    $i++;
}
file_put_contents('add.txt', $windows_add);
file_put_contents('del.txt', $windows_del);
file_put_contents('routes-up-android.sh', $android_up);
file_put_contents('routes-down-android.sh', $android_down);
echo $i;