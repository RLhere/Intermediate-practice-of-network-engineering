<?php
    require("class.whois.php");
    $whois=new Whois;
    echo $whois->whoislookup("www.baidu.com");
?>