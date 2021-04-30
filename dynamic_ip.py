__author__ = 'Oscar Yang Liu'

import json

from PyQt5.QtCore import QUrlQuery, QUrl, QTimer, QSettings
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5 import QtNetwork
from resource.UI.main import Ui_main
from pyDes import des, CBC, PAD_PKCS5
import binascii


class DynamicIp(QWidget,Ui_main):
  def __init__(self, parent=None, *args, **kwargs):
    super().__init__(parent, *args, **kwargs)
    self.initUi()

  def initUi(self):
    self.setupUi(self)
    # 先取保存的变量
    self.settings = QSettings("yqfsoft", "DDNS")
    self.userinfo = self.settings.value('userinfo')

    if self.userinfo != None:
      self.domain_le.setText(self.userinfo['domain'])
      self.username_le.setText(self.userinfo['username'])
      self.password_le.setText(self.descrypt(self.userinfo['password']))
      self.update_time_le.setText(self.userinfo['update_time'])
      self.is_connected(not self.userinfo['editable'])
    #   https://ipv4.jsonip.com https://ipv6.jsonip.com https://jsonip.com
    self.ip_url = 'https://jsonip.com'
    self.get(self.ip_url)


  def start_update_ip(self):
    # self.timer.timeout.connect(lambda: self.get('https://jsonip.com/'))
    domain = self.domain_le.text()
    username = self.username_le.text()
    password = self.password_le.text()
    update_time = self.update_time_le.text()
    if domain !='' and username !='' and password !='' and update_time !='':
      # 密码加密保存到注册表
      encrypt_password = self.encrypt(password)
      editable = False
      self.is_connected(not editable)
      self.userinfo = {'domain':domain,'username':username,'password':encrypt_password,'update_time':update_time,'editable':editable}
      self.settings.setValue('userinfo',self.userinfo)



  def edit_info(self):
    print('change被点击了')
    self.is_connected(False)
    self.userinfo['editable'] = True
    self.settings.setValue('userinfo',self.userinfo)


  def is_connected(self,state:bool):
    self.domain_le.setDisabled(state)
    self.username_le.setDisabled(state)
    self.password_le.setDisabled(state)
    self.update_time_le.setDisabled(state)
    self.ok_btn.setDisabled(state)

  def is_start_in_window(self,toggle):
    print('toogle',toggle)

  # get异步请求
  def get(self, url: str):
    # 创建一个请求
    path = QUrl(url)
    req = QtNetwork.QNetworkRequest(path)
    self.nam = QtNetwork.QNetworkAccessManager()
    self.nam.finished.connect(self.handleResponse)
    # 使用get请求 如果有参数的话 写一个data 放到get里
    self.nam.get(req)

  # 响应请求后发送时间
  def handleResponse(self, reply):
    er = reply.error()
    if er == QtNetwork.QNetworkReply.NoError:
      bytes_string = reply.readAll()
      bytes_to_json = json.loads(str(bytes_string,encoding='utf8'))
      self.ip_lb.setText(bytes_to_json['ip'])
      print(bytes_to_json['ip'])
    else:
      self.ip_lb.setText('')


  # 加密
  def encrypt(self,s):
    """
    DES 加密
    :param s: 原始字符串
    :return: 加密后字符串，16进制
    """
    secret_key = 'fd+25_*4'  # 密码 要求8位
    iv = secret_key  # 偏移
    # secret_key:加密密钥，CBC:加密模式，iv:偏移, padmode:填充
    des_obj = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    # 返回为字节
    secret_bytes = des_obj.encrypt(s, padmode=PAD_PKCS5)
    # 返回为16进制
    return binascii.b2a_hex(secret_bytes)

  # 解密
  def descrypt(self,s):
    """
    DES 解密
    :param s: 加密后的字符串，16进制
    :return:  解密后的字符串
    """
    secret_key = 'fd+25_*4' # 要求8位
    iv = secret_key
    des_obj = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    decrypt_str = des_obj.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
    return str(decrypt_str,encoding='utf8')

if __name__ == '__main__':
  import sys
  app = QApplication(sys.argv)
  window = DynamicIp()
  window.show()
  sys.exit(app.exec_())