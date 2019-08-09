#!/usr/bin/python
#-*-coding:utf-8-*-
import os
import time
import sys
import logging
import sqlite3
from serverids_common import ServeridsCommon
from serverids_custom import recover_custom
from ConfigParser import ConfigParser
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s -- %(levelname)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S", filename = "/var/skyeye/xenadmin.log")
from insert_db import DbProcess
import sys
sys.path.append("/opt/work/serverids/release/src")


def main():
    logging.info("----------------upgrade_start-------------------")
    username = sys.argv[1]
    userip = sys.argv[2]
    update_time = ServeridsCommon.get_ctime()
    serialno = ServeridsCommon.get_device_serial()
    old_rule_version = ServeridsCommon.get_rule_version()

    logging.info(username)
    logging.info(userip)
    logging.info(update_time)
	# 备份serverids.cfg文件
    back_conf = "/tmp/serverids"
    new_conf = "/opt/work/serverids/release/src/serverids.cfg"
    os.system("cp -rf /opt/work/serverids/release/src/serverids.cfg /tmp/serverids.cfg_bak")

    cwd = os.getcwd()
    logging.info(cwd)

    ret = os.popen('netstat -anp|grep "127.0.0.1:7311"|grep LISTEN|wc -l').read().strip()
    logging.info("redis 7311 stat:%s"%ret)
    
    logging.info("stop serverids group")
    os.system('supervisorctl stop serverids:*')
    time.sleep(2)
    
    if ret == '0':
        logging.info("Clean Redis 6379")
        os.system('>/var/lib/redis/redis_6379.aof')
    else:
        logging.info("Clean Redis 7311")
        os.system('>/var/lib/redis/redis_7311.aof')

    logging.info("move file...")
    os.system('\cp -rf opt /')
    time.sleep(1)

    BasePath = '/opt/work/serverids/release/src/insertDB/'
    conf_path = BasePath + 'conf/insertDB.conf'
    db_process = DbProcess(conf_path)
    db_process.GetVersionOfDevice()
    version = db_process.DeviceVersion
    if version == '3.0.3.1':
        os.system("rm -f /opt/work/serverids/release/rule/server_disc_desc.xml")

    # high low device version
    logging.info("change serverids.cfg...")
    if ServeridsCommon.check_device_hardware_version() == 0:
        cmd = "mv /opt/work/serverids/release/src/serverids-low.cfg /opt/work/serverids/release/src/serverids.cfg"
        os.system(cmd)
    else:
        cmd = "mv /opt/work/serverids/release/src/serverids-high.cfg /opt/work/serverids/release/src/serverids.cfg"
        os.system(cmd)
    # 备份下serverids.cfg供重置高级参数用
    cmd = "cp /opt/work/serverids/release/src/serverids.cfg /opt/work/serverids/release/src/serverids.cfg_origin"
    os.system(cmd)
    os.system("chown webapi:webapi /opt/work/serverids/release/src/serverids.cfg_origin")

    # high low device version
    logging.info("change QnaConf.xml...")
    if ServeridsCommon.check_device_hardware_version() == 0:
        cmd = "mv /opt/work/serverids/release/src/QnaConf.xml.low /etc/conf/qna-inspect/QnaConf.xml"
        os.system(cmd)
    else:
        cmd = "mv /opt/work/serverids/release/src/QnaConf.xml.mid /etc/conf/qna-inspect/QnaConf.xml"
        os.system(cmd)

    logging.info("xml update")
    # 判断是中文版或英文版
    webrule_file = 'webrule.xml'
    webshell_file = 'webshell.xml'
    serverids_rule_add_info_file = 'serverids_rule_add_info.xml'
    ips_rule_file = 'ips_rule.xml'
    lang = ServeridsCommon.get_language() 
    
    table_list = [
                    'attack_no_table',
                    'ips_affected_systems', 
                    'ips_info_ids', 
                    'ips_rule', 
                    'ips_rule_affected_map',
                    'ips_rule_infoid_map', 
                    'ips_signature', 
                    'webrule', 
                    'webshell'
                ]
    if lang == 'EN':
        if os.path.exists('/opt/work/serverids/release/rule/webrule_en.xml'):
            webrule_file = 'webrule_en.xml'
        if os.path.exists('/opt/work/serverids/release/rule/webshell_en.xml'):
            webshell_file = 'webshell_en.xml'
        if os.path.exists('/opt/work/serverids/release/rule/serverids_rule_add_info_en.xml'):
            serverids_rule_add_info_file = 'serverids_rule_add_info_en.xml'
        if os.path.exists('/opt/work/serverids/release/rule/ips_rule_en.xml'):
            ips_rule_file = 'ips_rule_en.xml'

    args = [{'xml': serverids_rule_add_info_file, 'table': 'attack_no_table', 'conf': ''},
            {'xml': 'ips_affected_systems.xml', 'table': 'ips_affected_systems', 'conf': ''},
            {'xml': 'ips_info_ids.xml', 'table': 'ips_info_ids', 'conf': ''},
            {'xml': ips_rule_file, 'table': 'ips_rule', 'conf': 'ids_disable_rule.conf'}, 
            {'xml': 'ips_rule_affected_map.xml', 'table': 'ips_rule_affected_map', 'conf': ''},
            {'xml': 'ips_rule_infoid_map.xml', 'table': 'ips_rule_infoid_map', 'conf': ''},
            {'xml': 'ips_signature.xml', 'table': 'ips_signatures', 'conf': ''},
            {'xml': webrule_file, 'table': 'webids_rule_desc', 'conf': 'vulnerability_disable_rule.conf'}, 
            {'xml': webshell_file, 'table': 'webshell_alert_desc', 'conf': 'webshell_disable_rule.conf'}]

    rule_path = "/opt/work/serverids/release/rule/"
    conf_path = "/opt/work/serverids/release/conf/"

    if version >= "3.0.6.1":
        from insert_rule2db import RuleTranslator
        rule_translator = RuleTranslator()
        # 获取需要保存的用户自定义配置
        ips_custom_rules = rule_translator.get_custom_rules('ips_rule')
        webids_custom_rules = rule_translator.get_custom_rules('webids_rule_desc')
        webshell_custom_rules = rule_translator.get_custom_rules('webshell_alert_desc')
        # 清空db中的规则
        rule_translator.clear_table()
        try:
            for item in args:
                item['xml'] = rule_path + item['xml']
                item['conf'] = conf_path + item['conf']
                rule_translator.update(item['xml'], item['table'], item['conf'])
        except Exception as e:
            logging.info(str(e))
        '''
        for i in table_list:
            try:
                target_xml = '/opt/work/serverids/release/rule/%s.xml'%(i)
                if i == 'attack_no_table':
                    target_table = 'attack_no_table'
                    target_xml = '/opt/work/serverids/release/rule/serverids_rule_add_info.xml'
                    rule_translator.update(target_xml, target_table, "")
                elif i == 'ips_signature':
                    target_table = 'ips_signatures'
                    rule_translator.update(target_xml, target_table, "")
                elif i == 'ips_rule':
                    target_table = 'ips_rule'
                    target_conf = '/opt/work/serverids/release/conf/ids_disable_rule.conf'
                    rule_translator.update(target_xml, target_table, target_conf)
                elif i == 'webrule':
                    target_table = 'webids_rule_desc'
                    target_conf = '/opt/work/serverids/release/conf/vulnerability_disable_rule.conf'
                    rule_translator.update(target_xml, target_table, target_conf)
                elif i == 'webshell':
                    target_table = 'webshell_alert_desc'
                    target_conf = '/opt/work/serverids/release/conf/webshell_disable_rule.conf'
                    rule_translator.update(target_xml, target_table, target_conf)
                else:
                    target_table = i
                    rule_translator.update(target_xml, target_table, "")
            except Exception as e:
                logging.info(str(e))
        '''
		# 修改用户自定义配置
        rule_translator.update_custom('webids_rule_desc', webids_custom_rules)
        rule_translator.update_custom('ips_rule', ips_custom_rules)
        rule_translator.update_custom('webshell_alert_desc', webshell_custom_rules)
        conf_dir = '/opt/work/serverids/release/conf/'
        # 修改disable_conf
        # 修改webshell_disable_rule
        rule_translator.change_backdoor_disable_rule_conf(os.path.join(conf_dir, 'webshell_disable_rule.conf'))
        # 修改vulnerability_disable_rule
        rule_translator.change_rule_disable_rule_conf(os.path.join(conf_dir, 'vulnerability_disable_rule.conf'))
        # 修改ids_disable_rule.conf
        rule_translator.change_ids_disable_rule_conf(os.path.join(conf_dir, 'ids_disable_rule.conf'))
    else:
        for i in table_list:
            python = '/opt/work/web/sensor/env/bin/python'
            script = '/opt/work/serverids/release/update/ids_xml_translator.py'
            target_db = '/data/serverids/serverids.db'
            target_xml = '/opt/work/serverids/release/rule/%s.xml'%(i)
            if i == 'ips_signature':
                target_table = 'ips_signatures'
                cmd = '%s %s -db %s -xml %s -table %s'%(python, script, target_db, target_xml, target_table)
            elif i == 'ips_rule':
                target_table = 'ips_rule'
                target_conf = '/opt/work/serverids/release/conf/ids_disable_rule.conf'
                cmd = '%s %s -db %s -xml %s -table %s -conf %s'%(python, script, target_db, target_xml, target_table, target_conf)
            elif i == 'webrule':
                target_table = 'webids_rule_desc'
                target_conf = '/opt/work/serverids/release/conf/vulnerability_disable_rule.conf'
                cmd = '%s %s -db %s -xml %s -table %s -conf %s'%(python, script, target_db, target_xml, target_table, target_conf)
            elif i == 'webshell':
                target_table = 'webshell_alert_desc'
                target_conf = '/opt/work/serverids/release/conf/webshell_disable_rule.conf'
                cmd = '%s %s -db %s -xml %s -table %s -conf %s'%(python, script, target_db, target_xml, target_table, target_conf)
            else:
                target_table = i
                cmd = '%s %s -db %s -xml %s -table %s'%(python, script, target_db, target_xml, target_table)
            logging.debug(cmd)
            os.system(cmd)
    if (version >= "3.0.6.1" and version < "3.0.6.4") or (version >= "4.0.6.1" and version < "4.0.6.4") or version in ["3.0.7.1","4.0.7.1","3.0.7.2","4.0.7.2"]:
        python = '/opt/work/web/sensor/env/bin/python'
        script = '/opt/work/serverids/release/other/ioc/ioc_preprocess_rule.py'
        raw_ioc_file = '/opt/work/serverids/release/conf/ioc_rule_cloud.xml'
        simple_ioc_file = '/opt/work/serverids/release/conf/ioc_rule_cloud.hs'
        cache_dir = '/opt/work/serverids/release/src/data/cache/ioc/hyperscan.bak'
        if os.path.exists(cache_dir):
            logging.info("clear old ioc cache")
            os.system("rm -rf /opt/work/serverids/release/src/data/cache/ioc/hyperscan.bak")
        if os.path.exists(raw_ioc_file):
            cmd = '%s %s -iocnomd5 %s -iochs %s'%(python, script, raw_ioc_file, simple_ioc_file)
            logging.debug(cmd)
            os.system(cmd)
        ioc_compile_server = '/opt/work/serverids/release/src/ioc_compile_server'
        if os.path.exists(ioc_compile_server):
            cmd = "%s -f /opt/work/serverids/release/conf/ioc_compile_server.cfg"%ioc_compile_server
            logging.debug(cmd)
            ret = os.system(cmd)
            cache_list_str = os.popen("ls -lrt /opt/work/serverids/release/src/data/cache/ioc/hyperscan").read()
            logging.debug("retcode: %s , ioc cache dir: %s"%(ret, cache_list_str))
    time.sleep(3)
    logging.info("start serverids group")
    # 恢复serverids.cfg配置
    try:
        recover_custom()
    except Exception as e:
        print e
    os.system('supervisorctl start serverids:*')
    cmd = "chown webapi:webapi /opt/work/serverids/release/src/serverids.cfg"
    os.system(cmd)
    
    new_rule_version = ServeridsCommon.get_rule_version()
    if version >= "3.0.6.1":
        try:
            attr_dic = {}
            attr_dic["version"] = new_rule_version
            attr_dic["updatetime"] = update_time
            attr_dic["type"] = 1
            attr_dic["user"] = username
            attr_dic["note"] = ""
            attr_dic["type"] = 204
            attr_dic["ip"] = userip
            db_process.insert_update_log(attr_dic)
            
            attr_dic = {}
            attr_dic["logtype"] = 1
            attr_dic["level"] = 5
            attr_dic["updatetime"] = update_time
            if lang == 'CH':
                attr_dic["note"] = u"规则从{0}版本升级到{1}版本".format(old_rule_version, new_rule_version)
            else:
                attr_dic["note"] = u"Rules upgraded from {0} to {1}".format(old_rule_version, new_rule_version)

            attr_dic["serialno"] = serialno
            db_process.insert_monitor_log(attr_dic)
        except Exception, e:
            logging.error(e)
            raise e
    else:
        try:
            db = "/opt/work/web/sensor/data/update.db"
            conn = sqlite3.connect(db)
            cursor = conn.cursor()
            sql = "insert into update_log(version, updatetime, type, user, note, updatetype, ip) values('%s', '%s', 1, '%s', '', %s, '%s');"%(\
                                    new_rule_version, update_time, username, 204, userip)
            logging.info(sql)
            cursor.execute(sql)
            cursor.close()
            conn.commit()
            conn.close()
        except Exception, e:
            logging.error(e)
            raise e
    logging.info("----------------upgrade_finish-------------------")


if __name__ == '__main__':
    main()
