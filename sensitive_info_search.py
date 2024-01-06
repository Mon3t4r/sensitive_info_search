# js file sensitive information collection tool
# by laohuan12138 https://github.com/laohuan12138
# best1a 二开说明:1.合并了findsomething中的正则
#                2.增加本地文件读取功能,指定文件夹全量搜索 -l参数指定即可
#                3.将正则中出现频繁和需要爆破的信息如path,url,domain合并整理到输出文件

import requests
import urllib3
import re
urllib3.disable_warnings()
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from prettytable import PrettyTable
import optparse
import datetime
import os
from tqdm import tqdm
import time

regex = {
    'Email' : r'(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))',
    'Oss云存储桶' : r'([A|a]ccess[K|k]ey[I|i]d|[A|a]ccess[K|k]ey[S|s]ecret|[Aa]ccess-[Kk]ey)|[A|a]ccess[K|k]ey',
    "aliyun_oss_url": r"[\\w.]\\.oss.aliyuncs.com",
    "secret_key": r"[Ss](ecret|ECRET)_?[Kk](ey|EY)",
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'wechat' : r"(" \
           r"[W|w][X|x][I|i][D|d]:[\"]?[0-9a-zA-Z]+\[\"]?" \
           r"|[A|a][P|p][P|p][I|i][D|d]:[\"]?[0-9a-zA-Z]+[\"]?" \
           r"|[A|a][P|p][P|p][K|k][E|e][Y|y]:[\"]?[0-9a-zA-Z]+[\"]?" \
           r"|[A|a][P|p][P|p][S|s][E|e][C|c][R|r][E|e][T|t]]:[\"]?[0-9a-zA-Z]+[\"]?)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
#    'possible_Creds' : r"(?i)(" \
 #                   r"password\s*[`=:\"]+\s*[^\s]+|" \
 #                   r"password is\s*[`=:\"]*\s*[^\s]+|" \
 #                   r"pwd\s*[`=:\"]*\s*[^\s]+|" \
 #                   r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'Artifactory API Token': r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    'Artifactory Password': r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    'AWS Client ID': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
#    'Base64': r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}',
    'Basic Auth Credentials': r'(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+',
    'Cloudinary Basic Auth': r'cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
    "Facebook Client ID": r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}",
    "Facebook Secret Key": r"(?i)(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}",
    "Github": r"(?i)github(.{0,20})?['\"][0-9a-zA-Z]{35,40}",
    "Google Cloud Platform API Key": r"(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
    "LinkedIn Secret Key": r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
    'Mailchamp API Key': r"Mailchamp API Key",
    'Mailchamp API Key' : r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Mailgun API Key' : r'key-[0-9a-zA-Z]{32}',
    'Picatic API Key' : r'sk_live_[0-9a-z]{32}',
    'Slack Token' : r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    'Slack Webhook' : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'Stripe API Key' : r'(?:r|s)k_live_[0-9a-zA-Z]{24}',
    'Square Access Token' : r'sqOatp-[0-9A-Za-z\\-_]{22}',
    'Square Oauth Secret' : r'sq0csp-[ 0-9A-Za-z\\-_]{43}',
    "witter Oauth" : r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "Twitter Secret Key" : r"(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}",
    "国内手机号码" : r'1(3|4|5|6|7|8|9)\d{9}',
    "身份证号码" : r"[1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]",
    'IP地址' : r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    "Secret Key OR Private API" : "(access_key|Access-Key|access_token|SecretKey|SecretId|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps|AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc|password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot|files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.\-,]{0,25}[a-z0-9A-Z_ .\-,]{0,25}(=|>|:=|\||:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{6,64})['\"]",
    'path':r"['\"](?:\/|\.\.\/|\.\/)[^\/><\(\){},'\"\\]([^><\(\){},'\"\\])*?['\"]",
    'url':r"['\"](([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\:\d{1,5})?(\/.*?)?['\"]",
    'ip':r"['\"](([a-zA-Z0-9]+:)?\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    "ip:port":r"['\"](([a-zA-Z0-9]+:)?\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}(\/.*?)?['\"]",
    "domain":r"['\"](([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\:\d{1,5})?",
    'incomplete_path':r"['\"][^\/\>\<\)\(\{\}\,\'\"\\][\w\/]*?\/[\w\/]*?['\"]",
    'jwt':r"['\"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})['\"]",
    'algorithm':r"\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|$\.md5|md5|sha1|sha256|sha512)[\(\.]",
    'nuclei_规则':r"(" \
            r"[\"']?zopim[_-]?account[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?zhuliang[_-]?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?zensonatypepassword[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?zendesk[_-]?travis[_-]?github[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?server[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?partner[_-]?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?partner[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?account[_-]?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yt[_-]?account[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yangshun[_-]?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?yangshun[_-]?gh[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?www[_-]?googleapis[_-]?com[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?ssh[_-]?connect[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?report[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?prepare[_-]?dir[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?db[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpt[_-]?db[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wporg[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wordpress[_-]?db[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wordpress[_-]?db[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wincert[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?test[_-]?server[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?fb[_-]?password[_-]?3[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?fb[_-]?password[_-]?2[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?fb[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?basic[_-]?password[_-]?5[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?basic[_-]?password[_-]?4[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?basic[_-]?password[_-]?3[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?basic[_-]?password[_-]?2[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?widget[_-]?basic[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?watson[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?watson[_-]?device[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?watson[_-]?conversation[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?wakatime[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?vscetoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?visual[_-]?recognition[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?virustotal[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?vip[_-]?github[_-]?deploy[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?v[_-]?sfdc[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?v[_-]?sfdc[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?usertravis[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?user[_-]?assets[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?user[_-]?assets[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?use[_-]?ssh[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?urban[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?urban[_-]?master[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?urban[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?unity[_-]?serial[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?unity[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twitteroauthaccesstoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twitteroauthaccesssecret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twitter[_-]?consumer[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twitter[_-]?consumer[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twine[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?configuration[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?api[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?twilio[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?trex[_-]?okta[_-]?client[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?trex[_-]?client[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?secure[_-]?env[_-]?vars[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?pull[_-]?request[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?e2e[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?com[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?branch[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?travis[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?token[_-]?core[_-]?java[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?thera[_-]?oss[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?tester[_-]?keys[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?test[_-]?test[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?test[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?tesco[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?svn[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?surge[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?surge[_-]?login[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?stripe[_-]?public[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?stripe[_-]?private[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?strip[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?strip[_-]?publishable[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?stormpath[_-]?api[_-]?key[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?stormpath[_-]?api[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?starship[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?starship[_-]?account[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?star[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?star[_-]?test[_-]?location[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?star[_-]?test[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?staging[_-]?base[_-]?url[_-]?runscope[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ssmtp[_-]?config[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sshpass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?srcclr[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sqssecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sqsaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?spring[_-]?mail[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?spotify[_-]?api[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?spotify[_-]?api[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?spaces[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?spaces[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?soundcloud[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?soundcloud[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatypepassword[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?token[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?token[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?nexus[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?gpg[_-]?passphrase[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonatype[_-]?gpg[_-]?key[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonar[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonar[_-]?project[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sonar[_-]?organization[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?socrata[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?socrata[_-]?app[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?snyk[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?snyk[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?snoowrap[_-]?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?snoowrap[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?snoowrap[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?slate[_-]?user[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?slash[_-]?developer[_-]?space[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?slash[_-]?developer[_-]?space[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?signing[_-]?key[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?signing[_-]?key[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?signing[_-]?key[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?signing[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?setsecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?setdstsecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?setdstaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ses[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ses[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?service[_-]?account[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sentry[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sentry[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sentry[_-]?endpoint[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sentry[_-]?default[_-]?org[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sentry[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendwithus[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sendgrid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?selion[_-]?selenium[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?selion[_-]?log[_-]?level[_-]?dev[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?segment[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secretaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?key[_-]?base[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?9[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?8[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?7[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?6[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?5[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?4[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?3[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?2[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?11[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?10[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?1[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?secret[_-]?0[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sdr[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?scrutinizer[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sauce[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sandbox[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?salesforce[_-]?bulk[_-]?test[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sacloud[_-]?api[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sacloud[_-]?access[_-]?token[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?sacloud[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?user[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?secret[_-]?assets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?secret[_-]?app[_-]?logs[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?key[_-]?assets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?key[_-]?app[_-]?logs[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?bucket[_-]?name[_-]?assets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?bucket[_-]?name[_-]?app[_-]?logs[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?s3[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rubygems[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rtd[_-]?store[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rtd[_-]?key[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?route53[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ropsten[_-]?private[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rinkeby[_-]?private[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rest[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?repotoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?reporting[_-]?webdav[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?reporting[_-]?webdav[_-]?pwd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?release[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?release[_-]?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?registry[_-]?secure[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?registry[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rediscloud[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?redis[_-]?stunnel[_-]?urls[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?randrmusicapiaccesstoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?rabbitmq[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?quip[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?qiita[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pypi[_-]?passowrd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pushover[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?publish[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?publish[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?publish[_-]?access[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?project[_-]?config[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?prod[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?prod[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?prod[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?private[_-]?signing[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pring[_-]?mail[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?preferred[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?prebuild[_-]?auth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?postgresql[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?postgresql[_-]?db[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?postgres[_-]?env[_-]?postgres[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?postgres[_-]?env[_-]?postgres[_-]?db[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?plugin[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?plotly[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?places[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?places[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pg[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pg[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?personal[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?personal[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?percy[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?percy[_-]?project[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?paypal[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?passwordtravis[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?parse[_-]?js[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?pagerduty[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?packagecloud[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ossrh[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ossrh[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ossrh[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ossrh[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ossrh[_-]?jira[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?os[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?os[_-]?auth[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?openwhisk[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?open[_-]?whisk[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?onesignal[_-]?user[_-]?auth[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?onesignal[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?omise[_-]?skey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?omise[_-]?pubkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?omise[_-]?pkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?omise[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?okta[_-]?oauth2[_-]?clientsecret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?okta[_-]?oauth2[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?okta[_-]?client[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ofta[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ofta[_-]?region[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ofta[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?octest[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?octest[_-]?app[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?octest[_-]?app[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?oc[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?object[_-]?store[_-]?creds[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?object[_-]?store[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?object[_-]?storage[_-]?region[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?object[_-]?storage[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?oauth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?numbers[_-]?service[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nuget[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nuget[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nuget[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?npm[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?now[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?non[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?node[_-]?pre[_-]?gyp[_-]?secretaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?node[_-]?pre[_-]?gyp[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?node[_-]?pre[_-]?gyp[_-]?accesskeyid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?node[_-]?env[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ngrok[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ngrok[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nexuspassword[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nexus[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?new[_-]?relic[_-]?beta[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?netlify[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?nativeevents[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysqlsecret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysqlmasteruser[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?root[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?hostname[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mysql[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?my[_-]?secret[_-]?env[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?multi[_-]?workspace[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?multi[_-]?workflow[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?multi[_-]?disconnect[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?multi[_-]?connect[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?multi[_-]?bob[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?minio[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?minio[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mile[_-]?zero[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mh[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mh[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mg[_-]?public[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mg[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mapboxaccesstoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mapbox[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mapbox[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mapbox[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?manifest[_-]?app[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?manifest[_-]?app[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mandrill[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?managementapiaccesstoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?management[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?manage[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?manage[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?secret[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?pub[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?pub[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?priv[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailgun[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailer[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailchimp[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mailchimp[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?mail[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?magento[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?magento[_-]?auth[_-]?username [\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?magento[_-]?auth[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lottie[_-]?s3[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lottie[_-]?happo[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lottie[_-]?happo[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?looker[_-]?test[_-]?runner[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ll[_-]?shared[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ll[_-]?publish[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?linux[_-]?signing[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?linkedin[_-]?client[_-]?secretor lottie[_-]?s3[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lighthouse[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lektor[_-]?deploy[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?lektor[_-]?deploy[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?leanplum[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kxoltsn3vogdop92m[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kubeconfig[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kubecfg[_-]?s3[_-]?path[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kovan[_-]?private[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?keystore[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kafka[_-]?rest[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kafka[_-]?instance[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?kafka[_-]?admin[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?jwt[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?jdbc:mysql[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?jdbc[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?jdbc[_-]?databaseurl[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?itest[_-]?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ios[_-]?docs[_-]?deploy[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?internal[_-]?secrets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?integration[_-]?test[_-]?appid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?integration[_-]?test[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?index[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ij[_-]?repo[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ij[_-]?repo[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hub[_-]?dxia2[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?homebrew[_-]?github[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hockeyapp[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?heroku[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?heroku[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?heroku[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hb[_-]?codesign[_-]?key[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hb[_-]?codesign[_-]?gpg[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hab[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?hab[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?grgit[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gren[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gradle[_-]?signing[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gradle[_-]?signing[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gradle[_-]?publish[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gradle[_-]?publish[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?secret[_-]?keys[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?private[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?passphrase[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?ownertrust[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?keyname[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gpg[_-]?key[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?private[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?maps[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?client[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?client[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?google[_-]?account[_-]?type[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gogs[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gitlab[_-]?user[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?tokens[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?repo[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?release[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?pwd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?oauth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?oauth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?hunter[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?hunter[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?deployment[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?auth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?github[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?committer[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?committer[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?author[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?git[_-]?author[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ghost[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ghb[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?repo[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?oauth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?oauth[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?next[_-]?oauth[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gh[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gcs[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gcr[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gcloud[_-]?service[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gcloud[_-]?project[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?gcloud[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?pw[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?login[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ftp[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?fossa[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?flickr[_-]?api[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?flickr[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?flask[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firefox[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firebase[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firebase[_-]?project[_-]?develop[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firebase[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firebase[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?firebase[_-]?api[_-]?json[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?file[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?exp[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?eureka[_-]?awssecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?sonatype[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?heroku[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?env[_-]?github[_-]?oauth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?end[_-]?user[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?encryption[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?elasticsearch[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?elastic[_-]?cloud[_-]?auth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dsonar[_-]?projectkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dsonar[_-]?login[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?droplet[_-]?travis[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dropbox[_-]?oauth[_-]?bearer[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?doordash[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dockerhubpassword[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dockerhub[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?postgres[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?passwd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?docker[_-]?hub[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?digitalocean[_-]?ssh[_-]?key[_-]?ids[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?digitalocean[_-]?ssh[_-]?key[_-]?body[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?digitalocean[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?dgpg[_-]?passphrase[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?deploy[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?deploy[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?deploy[_-]?secure[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?deploy[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ddgc[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ddg[_-]?test[_-]?email[_-]?pw[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ddg[_-]?test[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?pw[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?db[_-]?connection[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?datadog[_-]?app[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?datadog[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?port[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?database[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?danger[_-]?github[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cypress[_-]?record[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?coverity[_-]?scan[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?coveralls[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?coveralls[_-]?repo[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?coveralls[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cos[_-]?secrets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?conversation[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?conversation[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?v2[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?test[_-]?org[_-]?cma[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?php[_-]?management[_-]?test[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?management[_-]?api[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?integration[_-]?management[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?cma[_-]?test[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?contentful[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?consumerkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?consumer[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?conekta[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?coding[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?codecov[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?codeclimate[_-]?repo[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?codacy[_-]?project[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cocoapods[_-]?trunk[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cocoapods[_-]?trunk[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cn[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cn[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?clu[_-]?ssh[_-]?private[_-]?key[_-]?base64[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?clu[_-]?repo[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudinary[_-]?url[_-]?staging[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudinary[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudflare[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudflare[_-]?auth[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudflare[_-]?auth[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudflare[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?service[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?processed[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?parsed[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?order[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?instance[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?audited[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloudant[_-]?archived[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cloud[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?clojars[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cli[_-]?e2e[_-]?cma[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?claimr[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?claimr[_-]?superuser[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?claimr[_-]?db[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?claimr[_-]?database[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ci[_-]?user[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ci[_-]?server[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ci[_-]?registry[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ci[_-]?project[_-]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ci[_-]?deploy[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?chrome[_-]?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?chrome[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cheverny[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cf[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?certificate[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?censys[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cattle[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cattle[_-]?agent[_-]?instance[_-]?auth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cattle[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cargo[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?cache[_-]?s3[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bx[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bx[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bundlesize[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?built[_-]?branch[_-]?deploy[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?browserstack[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?browser[_-]?stack[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?brackets[_-]?repo[_-]?oauth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?pwd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?pass[_-]?prod[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?auth[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bluemix[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintraykey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintray[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintray[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintray[_-]?gpg[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintray[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?bintray[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?b2[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?b2[_-]?app[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?awssecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?awscn[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?awscn[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?awsaccesskeyid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?ses[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?ses[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?secrets[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?config[_-]?secretaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?config[_-]?accesskeyid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aws[_-]?access[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?author[_-]?npm[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?author[_-]?email[_-]?addr[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?auth0[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?auth0[_-]?api[_-]?clientsecret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?assistant[_-]?iam[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifacts[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifacts[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifacts[_-]?bucket[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifacts[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?artifactory[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?argos[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?apple[_-]?id[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?appclientsecret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?app[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?app[_-]?secrete[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?app[_-]?report[_-]?token[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?app[_-]?bucket[_-]?perm[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?apigw[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?apiary[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?api[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?api[_-]?key[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?api[_-]?key[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aos[_-]?sec[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?aos[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?ansible[_-]?vault[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?android[_-]?docs[_-]?deploy[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?anaconda[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?amazon[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?amazon[_-]?bucket[_-]?name[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?alicloud[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?alicloud[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?alias[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?search[_-]?key[_-]?1[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?search[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?search[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?api[_-]?key[_-]?search[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?api[_-]?key[_-]?mcm[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?admin[_-]?key[_-]?mcm[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?admin[_-]?key[_-]?2[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?algolia[_-]?admin[_-]?key[_-]?1[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?air[-_]?table[-_]?api[-_]?key[\"']?[=:][\"']?.+[\"']"\
            r"|[\"']?adzerk[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?admin[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?account[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?access[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?access[_-]?key[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?account[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?username[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?password[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?username[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?accesskey[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?secret[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?bucket[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[\w_-]*?token[\w_-]*?[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"\
            r"|[\"']?[-]+BEGIN \w+ PRIVATE KEY[-]+)",
}

headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36'}
js_list = []
num = 0
table = PrettyTable()
table.field_names = ["id","Info_Name","Info_Value","From_File"]
is_show = False
table.align = "l"
path_list =[]
domain_list =[]
url_list =[]
printed_info = set()
excluded_formats = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.avi', '.mov','.ico','.webp','zip']#本地文件读取中排除的文件格式
def check_url(url,js_url):
    if "http" in js_url:
        url = url
    else:
        url = urlparse(url)
        url = url.scheme+"://"+url.netloc+'/'+js_url
    js_list.append(url)


def send(url):
    try:
        rsp = requests.get(url,timeout=10,headers=headers,verify=False)
        rsp_raw = rsp.content.decode("utf-8")
        html = BeautifulSoup(rsp_raw,"html.parser")

        script_src = html.findAll("script")
        for html_script in script_src:
            script_l = html_script.get("src")
            if re.search(r'(\.js)$',str(script_l)):
                check_url(url,script_l)


    except:
        print("\033[31m[-] %s Request failed !\033[0m" % url)
        pass
#    print(js_list)

def send_js(url):
    global rsp_raws
    try:
        rsp = requests.get(url, timeout=10, headers=headers, verify=False)
        rsp_raw = rsp.content.decode("utf-8")
        rsp_raws = rsp_raw.replace(";",";\r\n").replace(",",",\r\n")

    except:
        print("\033[31m[-] %s Request failed !\033[0m" % url)

    regex_se(rsp_raws,url)

def regex_se(content,url):
    global num
    global is_show
    str_table = []
    str_len = len(content)
    for i in regex.items():
        match_start = 0
        reg_list = []
        while match_start < str_len:
            reg_cont = content[match_start:str_len]
            regex_result = re.search(i[1],reg_cont,re.IGNORECASE)
            if regex_result:
                match_start += regex_result.end() + 1
                is_show = True
                if regex_result.group() not in reg_list:
                    info_log="\033[32m [+] Found\033[0m"+"\033[31m {} \033[0m".format(i[0])+"\033[32m in {} \033[0m".format(url)
                    if info_log not in printed_info:#不重复打印一样的信息
                        print(info_log)
                        printed_info.add(info_log)
                    if i[0] == 'path' or i[0] == 'incomplete_path':#发现实际中常常发现太多path,故分开处理展示
                        path_list.append(regex_result.group())
                    else:
                        if i[0] =="domain":#分开存储便于爆破等
                            domain_list.append(regex_result.group())
                        if i[0] =="url":  
                            url_list.append(regex_result.group())
                        num += 1
                        reg_list.append(regex_result.group())
                        str_table.append(num)
                        str_table.append(i[0])
                        str_table.append(regex_result.group())
                        str_table.append(url)
                        table.add_row(str_table)
                        
                        
                
                str_table.clear()
    
            else:
                break

def print_table():
    if is_show:
        print(table.get_string())
        date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        with open(date+'.txt','a+') as f:
            f.write(table.get_string())
            f.write("\n==============Path=================Path================Path===========Path===========Path========\n")
            for i in  path_list:
                f.write(i[1:-1]+'\n')
            f.write("\n=============Domain================Domain==================Domain==========Domain========Domain=========\n")
            for i in  domain_list:
                f.write(i[1:-1]+'\n')
            f.write("\n===============URl==================URl==============URl==========URl==========URl===========\n")
            for i in  url_list:
                f.write(i[1:-1]+'\n')
        print("\033[32m [+] 结果保存到 {} ！path,domain,url集合请在文件中查看.\033[0m".format(date+'.txt'))
    else:
        print("\033[32m [!] 未发现敏感信息!\033[0m")

def count_files_in_directory(path):
    # 列出指定路径下的所有文件和文件夹
    files = os.listdir(path)
    
    # 过滤出路径下的文件（排除文件夹）
    files = [f for f in files if os.path.isfile(os.path.join(path, f))]
    
    # 获取文件数量
    num_files = len(files)
    
    return num_files

def main():
    parser = optparse.OptionParser("python %prog -u http://127.0.0.1")
    parser.add_option('-u','--url',dest='url',help='输入一个URL，爬取URL中的所有js文件')
    parser.add_option('-f','--file',dest='file',help='批量爬取')
    parser.add_option('-j','--js',dest='js',help='输入指定的js文件')
    parser.add_option('-l','--path',dest='path',help='输入本地文件夹路径')
    options,args = parser.parse_args()
    if options.path: #增加本地文件夹读取功能
        path = options.path
        for root, dirs, files in os.walk(path):
            for file_name in files:
                if not any(file_name.endswith(format) for format in excluded_formats):
                    path = os.path.join(root, file_name)
                    # 读取文件内容
                    with open(path, 'r', errors='ignore') as file:
                        content = file.read()
                        # 在文件内容中进行正则匹配
                    regex_se(content,path)
                    # 处理匹配结果
    elif options.url:
        url = options.url.strip()
        send(url)
    elif options.file:
        file = options.file
        with open(file,'r') as f:
            for i in f:
                send(i.strip())
    elif options.js:
        url = options.js
        send_js(url.strip())
    else:
        parser.error("查看帮助信息 python %prog -h")

    print("\033[32m [+] Found %d js files\033[0m" % (len(js_list)))
    print("\033[33m [+] start matching！\033[0m")
    for i in js_list:
        send_js(i.strip())

    print("\033[33m [+] A total of %d results were matched\033[0m" % (num))
    print_table()


if __name__ == '__main__':
    main()
