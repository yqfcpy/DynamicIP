__author__ = 'Administrator'

import json

from PyQt5 import QtNetwork
from PyQt5.QtCore import QObject, pyqtSignal, QUrl, QUrlQuery, QJsonDocument


class AsyncRequest(QObject):
  getResult = pyqtSignal(dict)

  def __init__(self):
    super().__init__()

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

  def post(self, url: str, jsonBody: dict, param: dict = None):
    path = QUrl(url)
    sendData = QJsonDocument(jsonBody)
    if param != None:
      queryParams = QUrlQuery()
      for item in param.items():
        queryParams.addQueryItem(item[0], item[1])
      path.setQuery(queryParams.query())
    req = QtNetwork.QNetworkRequest(path)
    # 设置头信息是json这里可以不写
    # req.setHeader(QtNetwork.QNetworkRequest.ContentTypeHeader, "application/json")
    self.nam = QtNetwork.QNetworkAccessManager()
    self.nam.finished.connect(self.handleResponse)
    self.nam.post(req, sendData.toJson())

  def handleResponse(self, reply):
    # replay是发出信号后的返回值
    er = reply.error()
    # 如果返回值没有错误的话 执行
    if er == QtNetwork.QNetworkReply.NoError:
      bytes_string = reply.readAll()
      bytes_string_to_json = str(bytes_string, "utf-8")
      result = {'result': bytes_string_to_json}
      self.result = result
    else:
      errorResult = {'result': '{"success": "False"}'}
      self.result = errorResult
    self.getResult.emit(self.result)