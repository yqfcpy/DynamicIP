__author__ = 'Oscar Yang Liu'

import json

from PyQt5.QtCore import QUrlQuery, QUrl, QTimer, QSettings
from PyQt5.QtGui import QIntValidator, QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox, QSystemTrayIcon, QMenu, QAction, qApp
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
    # 设置文本可以跳转页面
    self.web_lb.setOpenExternalLinks(True)

    if self.userinfo != None:
      self.domain_le.setText(self.userinfo['domain'])
      self.username_le.setText(self.userinfo['username'])
      self.password_le.setText(self.descrypt(self.userinfo['password']))
      self.update_time_le.setText(self.userinfo['update_time'])
      self.is_connected(not self.userinfo['editable'])

    # https://ipv4.jsonip.com https://ipv6.jsonip.com https://jsonip.com
    self.ip_url = 'https://ipv4.jsonip.com'
    self.get(self.ip_url)
    self.request_ip_time = QTimer()


    # 验证时间的
    update_time_validator = QIntValidator(5,1092)
    self.update_time_le.setValidator(update_time_validator)

    # 信号
    self.request_ip_time.timeout.connect(lambda:print('时间超时'))



  def start_update_ip(self):
    if self.ip_lb.text() == '':
      return None
    domain = self.domain_le.text()
    username = self.username_le.text()
    password = self.password_le.text()
    if domain == '' or username == '' or password == '':
      return None
    if self.update_time_le.text() == '' or int(self.update_time_le.text())<5 or int(self.update_time_le.text())>1092:
      self.update_time_le.setText('5')
    update_time = self.update_time_le.text()
    if domain !='' and username !='' and password !='' and update_time !='':
      # 密码加密保存到注册表
      encrypt_password = self.encrypt(password)
      self.is_connected(True)
      self.userinfo = {'domain':domain, 'username':username, 'password':encrypt_password, 'update_time':update_time, 'editable':self.ok_btn.isEnabled()}
      self.settings.setValue('userinfo', self.userinfo)
    # 发送更新请求
    try:
      self.update_ip(username, password, domain, self.ip_lb)
    except:
      self.error_info_lb.setText("The user info maybe incorrect!")
      self.is_connected(False)


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
  def get(self, url: str, param: dict = None):
    # 创建一个请求
    path = QUrl(url)
    if param != None:
      query = QUrlQuery()
      for item in param.items():
        query.addQueryItem(item[0], item[1])
      path.setQuery(query.query())
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
      # 如果进来的时候已经是enable状态那么直接提交一个更新ip
      if self.userinfo['editable'] == False:
        self.update_ip(self.username, self.password, self.domain, bytes_to_json['ip'])
        self.request_ip_time.start(int(self.update_time_le) * 60 * 1000)

    else:
      self.ip_lb.setText('')

  # 更新ip
  # DynDns Api
  # self.update_ip_url = 'https://username:password@members.dyndns.org/v3/update'
  # self.get(self.update_ip_url,{'hostname':'域名','myip':'当前的ip地址'})
  # self.update_ip(bytes_to_json['ip'])
  def update_ip(self, username:str, password:str, domain:str, new_ip:str):
    url = 'https://{}:{}@members.dyndns.org/v3/update'.format(username, password)
    self.get(url, {'hostname': domain, 'myip': new_ip})

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

  # 退出程序保存
  def closeEvent(self, event):
    reply = QMessageBox.question(self, 'Message', "Are you sure to quit?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    # 判断返回值，如果点击的是Yes按钮，我们就关闭组件和应用，否则就忽略关闭事件
    if reply == QMessageBox.Yes:
      # 退出保存变量
      domain = self.domain_le.text()
      username = self.username_le.text()
      password = self.password_le.text()
      if self.update_time_le.text() == '' or int(self.update_time_le.text())<5 or int(self.update_time_le.text())>1092:
        self.update_time_le.setText('5')
      update_time = self.update_time_le.text()
      encrypt_password = self.encrypt(password)
      self.userinfo = {'domain': domain, 'username': username, 'password': encrypt_password,
                       'update_time': update_time, 'editable': self.ok_btn.isEnabled()}
      self.settings.setValue('userinfo', self.userinfo)

      event.accept()
    else:
      event.ignore()


if __name__ == '__main__':
  import sys
  app = QApplication(sys.argv)
  window = DynamicIp()
  window.show()
  sys.exit(app.exec_())