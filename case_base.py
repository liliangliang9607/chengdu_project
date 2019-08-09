from ctypes import *
import os
import commands
import inspect
from lxml import etree
import time


MaxQnaStreamDataArgCount = 16
FieldArgs = c_uint64*MaxQnaStreamDataArgCount

class ValueData(Structure):
    _fields_ = [
        ("value", c_uint64)
    ]

class BufData(Structure):
    _fields_ = [
        ("size", c_uint64),
        ("data", c_char_p)
    ]

class FieldData(Union):
    _anonymous_ = ("struct",)
    _fields_ = [
        ("struct", ValueData),
        ("struct", BufData)
    ]

class QnaSpinLock(Structure):
    _fields_ = [
        ("locked", c_uint32)
    ]


class QnaStreamContext(Structure):
    _fields_ = [
        ("bypass", c_uint, 1),
        ("appid", c_uint),
        ("createTime", c_longlong),
        ("lock", QnaSpinLock),
        ("data", c_void_p)
    ]

class QnaStreamData(Structure):
    _anonymous_ = ("union",)
    _fields_ = [
        ("dir", c_uint, 1),
        ("firstChunk", c_uint, 1),
        ("lastChunk", c_uint, 1),
        ("numericData", c_uint, 1),
        ("id", c_uint),
        ("union", FieldData),
        ("createTime", c_longlong),
        ("argsCount", c_uint32),
        ("args", c_uint64*MaxQnaStreamDataArgCount),
    ]

class QnaEventData(Structure):
    _fields_ = [
        ('moduleId', c_uint32),
        ('userData', c_void_p),
        ('extraTransferData', c_void_p),
        ('data', c_uint64*8),
    ]

def get_context_map(fname):
    context_map = dict()
    rootNode = etree.parse(fname)
    for fieldNode in rootNode.xpath(".//FieldList/Field"):
        context_map[fieldNode.attrib["name"]]=int(fieldNode.attrib["id"])
    return context_map

CONTEXT_MAP = get_context_map('../../../qna-config/config.xml')

class TestBase(object):
    def rule_alert(self, eventType, eventData):
        print "sunon........................................................"
        self.alertIdList.append(int(eventData.contents.data[0]))
        print alertIdList

    def setup(self):
        dirname = os.path.dirname(inspect.getfile(self.__class__))
        print dirname
        self.alertIdList = []
        os.chdir(dirname)
        self.dirname = dirname
        self.build_signature()
        self.dll = CDLL(os.path.join(dirname, "../../../qna-engine-framework/src/libqna_inspect.so"), mode = RTLD_GLOBAL)
        self.dll.QnaInitialize(os.path.join(dirname, "QnaConf.xml"), 1)
        self.QnaEventCallback = CFUNCTYPE (None, c_int, POINTER(QnaEventData))
        self._rule_alert = self.QnaEventCallback(self.rule_alert)
        self.eventHandle = c_int(0)
        self.eventType = c_int(12)
        if 0 != self.dll.QnaRegisterEvent(self.eventType, self._rule_alert, None, byref(self.eventHandle)):
            print "register event [Alert] failed."
        self.create_stream_context()
        self.context_set = set()

    def teardown(self):
        self.dll.QnaDestroyStreamContext(byref(self.stream_context))
        self.dll.QnaFinalize()
        #commands.getoutput('rm -rf sig.json* qna_data')

    def create_stream_context(self):
        engineContext = QnaStreamContext()
        serverIp = c_uint(0x12345678);
        clientIp = c_uint(0x11223344);
        print 'CreateSearchContext ...'
        assert(self.dll.QnaCreateStreamContext(byref(engineContext), 0, 6,
                byref(serverIp), 8888, byref(clientIp), 9999) == 0)
        self.stream_context = engineContext

    def push_data(self, field, data, numericData=False):
        engineContext = self.stream_context
        if numericData:
            streamData = QnaStreamData(id=CONTEXT_MAP[field], size=data, time=time.time(), numericData=1)
        else:
            if field not in self.context_set:
                streamData = QnaStreamData(id=CONTEXT_MAP[field], data=data, size=len(data), time=time.time(), firstChunk=1)
                self.context_set.add(field)
            else:
                streamData = QnaStreamData(id=CONTEXT_MAP[field], data=data, size=len(data), time=time.time(), lastChunk=1)
                self.context_set.discard(field)
        assert(self.dll.QnaPushStreamData(byref(engineContext), byref(streamData)) == 0)
