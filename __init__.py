# -*- coding: utf-8 -*-
#
# This file is part of EventGhost.
# Copyright © 2005-2016 EventGhost Project <http://www.eventghost.org/>
#
# EventGhost is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 2 of the License, or (at your option)
# any later version.
#
# EventGhost is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with EventGhost. If not, see <http://www.gnu.org/licenses/>.

# changelog
# 21-04-2018: 12:46 -7:00   K
# Complete rewrite. This is now a multi-threaded asynchronous overlapped IO
# pipe written in pure python using only the std lib. I have added commented
# lines detailing how this whole system works.
#
# 18-12-2017: 23:07 -7:00   K
# Adds multiple pipe connection support.

import sys
import ctypes
import threading
import platform
import traceback
from uuid import uuid4 as GUID

try:
    # noinspection PyPep8Naming
    import Queue as queue
except ImportError:
    import queue

from ctypes.wintypes import (
    FormatError,
    HANDLE,
    ULONG,
    LPCSTR,
    LPCWSTR,
    DWORD,
    WORD,
    BOOL,
    BYTE,
    LPCVOID
)

from ctypes import POINTER

# various c types that get used when passing data to the Windows functions
PVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
LPDWORD = POINTER(DWORD)
PULONG = POINTER(ULONG)
LPTSTR = LPCSTR
LPCTSTR = LPTSTR
UCHAR = ctypes.c_ubyte
NULL = None

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_ulonglong
else:
    ULONG_PTR = ctypes.c_ulong

# returned values for WaitForSingleObject
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF

# can be passed to WaitForSingleObject
INFINITE = 0xFFFFFFFF

# bit identifiers for the pipe type, used in CreateNamedPipe
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_ACCESS_OUTBOUND = 0x00000002
PIPE_ACCESS_DUPLEX = 0x00000003

PIPE_UNLIMITED_INSTANCES = 0x000000FF

PIPE_TYPE_BYTE = 0x00000000
PIPE_TYPE_MESSAGE = 0x00000004

PIPE_READMODE_BYTE = 0x00000000
PIPE_READMODE_MESSAGE = 0x00000002

PIPE_WAIT = 0x00000000
PIPE_NOWAIT = 0x00000001

NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
NMPWAIT_NOWAIT = 0x00000001
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
FILE_FLAG_OPEN_NO_RECALL = 0x00100000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_OPEN_REQUIRING_OPLOCK = 0x00040000
FILE_FLAG_POSIX_SEMANTICS = 0x0100000
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_FLAG_SESSION_AWARE = 0x00800000
FILE_FLAG_RANDOM_ACCESS = 0x10000000
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000

FILE_ATTRIBUTE_NORMAL = 0x00000080

# bit identifiers passed to kernel32.OpenFile
OPEN_EXISTING = 0x00000003
GENERIC_ALL = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

# here for completeness
PIPE_CLIENT_END = 0x00000000
PIPE_SERVER_END = 0x00000001

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002

# return codes for a variety of the kernel32 functions
ERROR_INVALID_HANDLE = 0x00000006
ERROR_PIPE_CONNECTED = 0x00000217
ERROR_PIPE_LISTENING = 0x00000218
ERROR_BROKEN_PIPE = 0x0000006D
ERROR_PIPE_LOCAL = 0x000000E5
ERROR_MORE_DATA = 0x000000EA
ERROR_BAD_PIPE = 0x000000E6
ERROR_PIPE_BUSY = 0x000000E7
ERROR_NO_DATA = 0x000000E8
ERROR_PIPE_NOT_CONNECTED = 0x000000E9
ERROR_FILE_NOT_FOUND = 0x00000002
ERROR_ALREADY_EXISTS = 0x000000B7
ERROR_ACCESS_DENIED = 0x00000005
ERROR_IO_INCOMPLETE = 0x000003E4
ERROR_IO_PENDING = 0x000003E5
INVALID_HANDLE_VALUE = -1

# bit identifiers passed to FormatMessage located in PipeError
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

# Used to identify the current data state. PipeInstance class
CONNECTING_STATE = 0x00000000
READING_STATE = 0x00000001
WRITING_STATE = 0x00000002
MASTER = 0x00000016
SLAVE = 0x00000032


# we have to do some windows version checking. Windows 10 the pipe name needs
# to be formatted differently
WINDOWS_10 = platform.release() == '10'

# kernel32 API
kernel32 = ctypes.windll.kernel32
# Windows security API
advapi32 = ctypes.windll.advapi32


# c type structure that handles the overlapped io portion of the pipe
# noinspection PyPep8Naming
class _OVERLAPPED_STRUCTURE(ctypes.Structure):
    _fields_ = [
        ('Offset', DWORD),
        ('OffsetHigh', DWORD)
    ]


# noinspection PyPep8Naming
class _OVERLAPPED_UNION(ctypes.Union):
    _anonymous_ = ('_OVERLAPPED_STRUCTURE',)
    _fields_ = [
        ('_OVERLAPPED_STRUCTURE', _OVERLAPPED_STRUCTURE),
        ('Pointer', PVOID)
    ]


# noinspection PyPep8Naming
class _OVERLAPPED(ctypes.Structure):
    _anonymous_ = ('_OVERLAPPED_UNION',)
    _fields_ = [
        ('Internal', ULONG_PTR),
        ('InternalHigh', ULONG_PTR),
        ('_OVERLAPPED_UNION', _OVERLAPPED_UNION),
        ('hEvent', HANDLE)
    ]


OVERLAPPED = _OVERLAPPED
LPOVERLAPPED = ctypes.POINTER(_OVERLAPPED)


# c type security structures that set the security of the pipe
class _ACL(ctypes.Structure):
    _fields_ = [
        ('AclRevision', BYTE),
        ('Sbz1', BYTE),
        ('AclSize', WORD),
        ('AceCount', WORD),
        ('Sbz2', WORD)
    ]


ACL = _ACL
PACL = ctypes.POINTER(_ACL)


# noinspection PyPep8Naming
class _SECURITY_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ('Revision', UCHAR),
        ('Sbz1', UCHAR),
        ('Control', WORD),
        ('Owner', PVOID),
        ('Group', PVOID),
        ('Sacl', PACL),
        ('Dacl', PACL)
    ]


SECURITY_DESCRIPTOR = _SECURITY_DESCRIPTOR
PSECURITY_DESCRIPTOR = ctypes.POINTER(_SECURITY_DESCRIPTOR)


# noinspection PyPep8Naming
class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', DWORD),
        ('lpSecurityDescriptor', PSECURITY_DESCRIPTOR),
        ('bInheritHandle', BOOL)
    ]


SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
PSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)


DEFAULT_INSTANCES = 0x0000000A
DEFAULT_PACKET_SIZE = 0x00001000
DEFAULT_TIMEOUT = 0x000001F4
DEFAULT_SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES()
DEFAULT_SECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR()

advapi32.SetSecurityDescriptorDacl(
    ctypes.byref(DEFAULT_SECURITY_DESCRIPTOR),
    BOOL(1),
    NULL,
    BOOL(0)
)

DEFAULT_SECURITY_ATTRIBUTES.lpSecurityDescriptor = (
    DEFAULT_SECURITY_DESCRIPTOR
)
DEFAULT_SECURITY_ATTRIBUTES.nLength = (
    ctypes.sizeof(DEFAULT_SECURITY_ATTRIBUTES)
)


def _decl(name, ret=None, args=()):
    fn = getattr(kernel32, name)
    fn.restype = ret
    fn.argtypes = args
    return fn


GetLastError = kernel32.GetLastError

GetNamedPipeClientProcessId = _decl(
    'GetNamedPipeClientProcessId',
    BOOL,
    (HANDLE, PULONG)
)
GetNamedPipeClientSessionId = _decl(
    'GetNamedPipeClientSessionId',
    BOOL,
    (HANDLE, PULONG)
)
GetNamedPipeServerProcessId = _decl(
    'GetNamedPipeServerProcessId',
    BOOL,
    (HANDLE, PULONG)
)
GetNamedPipeServerSessionId = _decl(
    'GetNamedPipeServerSessionId',
    BOOL,
    (HANDLE, PULONG)
)
DisconnectNamedPipe = _decl(
    'DisconnectNamedPipe',
    BOOL,
    (HANDLE,)
)
ResetEvent = _decl(
    'ResetEvent',
    BOOL,
    (HANDLE,)
)
FlushFileBuffers = _decl(
    'FlushFileBuffers',
    BOOL,
    (HANDLE,)
)
WaitForSingleObject = _decl(
    'WaitForSingleObject',
    DWORD,
    (HANDLE, DWORD)
)
WaitNamedPipe = _decl(
    'WaitNamedPipeA',
    BOOL,
    (LPCTSTR, DWORD)
)
SetNamedPipeHandleState = _decl(
    'SetNamedPipeHandleState',
    BOOL,
    (HANDLE, LPDWORD, LPVOID, LPVOID)
)
FormatMessage = _decl(
    'FormatMessageA',
    DWORD,
    (DWORD, LPCVOID, DWORD, DWORD, LPVOID, DWORD, LPCVOID)
)
CloseHandle = _decl(
    "CloseHandle",
    BOOL,
    (HANDLE,)
)
CreateEvent = _decl(
    "CreateEventA",
    HANDLE,
    (LPVOID, BOOL, BOOL, LPCWSTR)
)
CreateFile = _decl(
    "CreateFileA",
    HANDLE,
    (LPVOID, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)
)
CreateNamedPipe = _decl(
    "CreateNamedPipeA",
    HANDLE,
    (LPVOID, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPVOID)
)
ConnectNamedPipe = _decl(
    "ConnectNamedPipe",
    BOOL,
    (HANDLE, LPOVERLAPPED)
)
WriteFile = _decl(
    "WriteFile",
    BOOL,
    (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
)
ReadFile = _decl(
    "ReadFile",
    BOOL,
    (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
)
GetOverlappedResult = _decl(
    "GetOverlappedResult",
    BOOL,
    (HANDLE, LPOVERLAPPED, LPDWORD, BOOL)
)


write_lock = threading.Lock()


class LOGGING:
    logging = None

    @staticmethod
    def debug(data):
        with write_lock:
            data = 'DEBUG:  ' + data + '\n'
            if LOGGING.logging is True:
                sys.stdout.write(data)
            elif LOGGING.logging:
                LOGGING.logging.write(data)

    @staticmethod
    def error(data):
        with write_lock:
            data = '\n        '.join(data.split('\n'))
            data = 'ERROR:  ' + data + '\n'
            if LOGGING.logging is True:
                sys.stderr.write(data)
            elif LOGGING.logging:
                LOGGING.logging.write(data)


class PipeError(Exception):
    def __init__(self, msg):
        if isinstance(msg, int):
            buf = ctypes.create_string_buffer(4096)

            kernel32.FormatMessageA(
                DWORD(FORMAT_MESSAGE_FROM_SYSTEM),
                NULL,
                DWORD(msg),
                DWORD(0),
                buf,
                DWORD(4096),
                NULL
            )
            err = msg
            err_hex = '0x' + '{0:#0{1}X}'.format(msg, 10)[2:]
            msg = '{0} [{1}]'.format(buf.value.rstrip(), err_hex)
            self._msg = [msg, err]
        else:
            self._msg = [msg, None]

    def __getitem__(self, item):
        return self._msg[item]

    def __str__(self):
        return self._msg[0]


# formats the pipe name properly
def _create_pipe_name(name):
    if WINDOWS_10:
        return '\\\\.\\pipe\\LOCAL\\' + name
    else:
        return '\\\\.\\pipe\\' + name


# used to check the existence of the named pipe. This is a means to know
# whether or not EG is running
def is_pipe_running(name):
    pipe_handle = CreateNamedPipe(
        _create_pipe_name(name),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        DEFAULT_PACKET_SIZE,
        DEFAULT_PACKET_SIZE,
        50,
        NULL
    )
    err = GetLastError()
    CloseHandle(pipe_handle)

    if err:
        return True

    return False


# the main handler for a pipe connection.
class PipeInstance(object):

    def __init__(self, pipe_name, pipe_handle, packet_size):
        self.__client_wait = threading.Event()
        self.__pipe_name = pipe_name
        self.__pipe_handle = pipe_handle
        self.__packet_size = packet_size
        self.__read_queue = queue.Queue()
        self.__read_overlap = None
        self.__read_event = None
        self.__read_buffer = None

        # create an instance os the overlapped io structure
        self.__client_overlap = OVERLAPPED()

        # get an event handle from Windows
        self.__client_event = CreateEvent(
            NULL,  # default security attribute
            True,  # manual-reset event
            False,  # initial state
            NULL  # unnamed event object
        )

        # if for some reason Windows is not able to give us an event handle
        # stop everything right there
        if self.__client_event == NULL:
            err = GetLastError()
            raise PipeError(err)

        # set the event handle into the overlapped io instance
        self.__client_overlap.hEvent = self.__client_event

        # if a client is connected to the pipe
        self.has_client = False
        self.__pending_connection = False

        # threading bits
        self.__debug('IO worker starting')

        self.__lock = threading.RLock()
        self.__io_event = threading.Event()
        self.__io_read = threading.Thread(
            name='Server Pipe {0} Read Worker'.format(str(self.__pipe_handle)),
            target=self.__read_loop
        )
        self.__io_read.daemon = True
        self.__io_read.start()
        self.connect()

    @property
    def waiting_connection(self):
        return not self.__client_wait.isSet()

    def __debug(self, msg, *args):

        msg = 'SERVER: {0}: {1}'.format(self.__pipe_handle, msg)
        if args:
            msg = msg.format(*args)

        LOGGING.debug(msg)

    # since creating a closing pipe instances takes time to do, we only do it
    # once.
    # so to keep performance boosted as the cost of a very small amount of
    # memory use we reuse the pipe when the client disconnects or an error
    # takes place
    def reconnect(self):
        self.__debug('reconnecting')

        with self.__lock:
            # this disconnects the client end of the pipe it does not close the
            # pipe
            self.__client_wait.clear()
            DisconnectNamedPipe(self.__pipe_handle)
            # reset data storage containers
            self.__read_queue = queue.Queue()
            self.__read_overlap = None
            self.__read_event = None
            self.__read_buffer = None
            self.has_client = False
            self.__pending_connection = False
            ResetEvent(self.__client_event)

    # if the pipe is open or closed. closed means a client can no longer
    # connect to this pipe instance
    @property
    def is_open(self):
        return not self.__io_event.isSet()

    # closes the pipe instance
    def close(self):
        self.__debug('closing')

        self.__io_event.set()
        self.__client_wait.set()

        if threading.currentThread() != self.__io_read:
            self.__io_read.join(1.0)

        FlushFileBuffers(self.__pipe_handle)
        DisconnectNamedPipe(self.__pipe_handle)
        CloseHandle(self.__pipe_handle)
        CloseHandle(self.__read_event)
        self.__debug('closed')

    @property
    def has_data(self):
        return not self.__read_queue.empty()

    def read(self):
        if not self.has_data:
            raise PipeError('No data available')
        try:
            return self.__read_queue.get()
        finally:
            self.__read_queue.task_done()

    def write(self, data, callback=None):
        guid = GUID()

        def do(write_data, write_callback, write_guid):
            self.__debug('creating write overlap event')

            write_overlap = OVERLAPPED()
            write_event = CreateEvent(
                NULL,
                True,
                False,
                NULL
            )

            if write_event == NULL:
                err = GetLastError()
                raise PipeError(err)

            write_overlap.hEvent = write_event

            if self.__write(write_data, write_overlap):
                CloseHandle(write_overlap.hEvent)
                if write_callback:
                    write_callback(write_guid)
            else:
                result = 0

                while not result:

                    write_bytes = DWORD(0)
                    result = GetOverlappedResult(
                        self.__pipe_handle,
                        ctypes.byref(write_overlap),
                        ctypes.byref(write_bytes),
                        True
                    )

                    err = GetLastError()
                    if result:
                        if write_bytes.value == len(write_data):
                            self.__debug('pending data written')
                            CloseHandle(write_overlap.hEvent)

                            if write_callback:
                                write_callback(write_guid)
                        else:
                            result = 0

                    elif err not in (
                        ERROR_IO_PENDING,
                        ERROR_IO_INCOMPLETE
                    ):
                        CloseHandle(write_overlap.hEvent)
                        try:
                            raise PipeError(err)
                        except PipeError:
                            LOGGING.error(traceback.format_exc())
                            self.reconnect()
                            return

                    ResetEvent(write_overlap.hEvent)

        t = threading.Thread(target=do, args=(data, callback, guid))
        t.daemon = True

        try:
            return guid
        finally:
            t.start()

    def __write(self, write_buffer, write_overlap):
        self.__debug('writing pipe')
        result = WriteFile(
            self.__pipe_handle,
            LPCSTR(write_buffer),
            len(write_buffer),
            NULL,
            ctypes.byref(write_overlap)
        )

        err = GetLastError()

        if result:
            self.__debug('data written')
            return False
        if err == ERROR_IO_PENDING:
            self.__debug('data pending write')
            return True
        elif err:
            try:
                raise PipeError(err)
            except PipeError:
                LOGGING.error(traceback.format_exc())
            CloseHandle(write_overlap.hEvent)
            self.reconnect()
            return True

    def __reset_read(self):
        self.__debug('reset read even')
        CloseHandle(self.__read_event)
        self.__read_overlap = OVERLAPPED()
        self.__read_event = CreateEvent(NULL, True, False, NULL)
        if self.__read_event == NULL:
            err = GetLastError()
            raise PipeError(err)

        self.__read_overlap.hEvent = self.__read_event
        self.__read_buffer = ctypes.create_string_buffer(self.__packet_size)

    def __read(self):
        self.__debug('reading')
        result = ReadFile(
            self.__pipe_handle,
            self.__read_buffer,
            self.__packet_size,
            NULL,
            ctypes.byref(self.__read_overlap)
        )

        err = GetLastError()

        if result:
            read_buffer = self.__read_buffer.value
            if read_buffer:
                if read_buffer == 'stop_pipe':
                    self.close()
                else:
                    self.__debug('data received')
                    self.__read_queue.put(read_buffer)
                    self.__reset_read()

        elif err == ERROR_IO_PENDING:
            self.__debug('pending read')

        elif err in (
            ERROR_BROKEN_PIPE,
            ERROR_BAD_PIPE,
            ERROR_NO_DATA,
            ERROR_INVALID_HANDLE,
            ERROR_PIPE_NOT_CONNECTED
        ):
            self.reconnect()

        elif err:
            try:
                raise PipeError(err)
            except PipeError:
                LOGGING.error(traceback.format_exc())
                self.reconnect()

    def __read_loop(self):
        self.__debug('read thread started')
        while not self.__io_event.isSet():
            self.__client_wait.wait()
            if self.__io_event.isSet():
                continue

            with self.__lock:
                self.__debug('waiting for read event')
                read_bytes = DWORD(0)
                result = GetOverlappedResult(
                    self.__pipe_handle,
                    ctypes.byref(self.__read_overlap),
                    ctypes.byref(read_bytes),
                    True
                )

                err = GetLastError()

                if result:
                    if read_bytes.value != 0:
                        self.__debug('read event triggered')
                        if self.__read_buffer.value == 'stop_pipe':
                            self.close()
                            return

                        self.__read_queue.put(self.__read_buffer.value)

                elif err not in (ERROR_IO_PENDING, ERROR_IO_INCOMPLETE):
                    if err == ERROR_BROKEN_PIPE:
                        return
                    try:
                        raise PipeError(err)
                    except PipeError:
                        LOGGING.error(traceback.format_exc())
                        self.reconnect()
                        continue

                self.__reset_read()
                self.__read()

    def connect(self):
        result = ConnectNamedPipe(
            self.__pipe_handle,
            ctypes.byref(self.__client_overlap)
        )
        err = GetLastError()

        if result:
            pass

        elif err == ERROR_IO_PENDING:
            self.__debug('waiting for connection')
            result = GetOverlappedResult(
                self.__pipe_handle,
                ctypes.byref(self.__client_overlap),
                ctypes.byref(DWORD(0)),
                True
            )
            err = GetLastError()

            if not result:
                try:
                    raise PipeError(err)
                except PipeError:
                    LOGGING.error(traceback.format_exc())
                self.reconnect()

                return

        elif err == ERROR_PIPE_CONNECTED:
            pass

        elif err:
            raise PipeError(err)

        self.has_client = True
        self.__debug('client connected')

        client_process_id = ULONG(0)
        client_session_id = ULONG(0)
        server_process_id = ULONG(0)
        server_session_id = ULONG(0)

        GetNamedPipeClientProcessId(
            self.__pipe_handle,
            ctypes.byref(client_process_id)
        )
        GetNamedPipeClientSessionId(
            self.__pipe_handle,
            ctypes.byref(client_session_id)
        )
        GetNamedPipeServerProcessId(
            self.__pipe_handle,
            ctypes.byref(server_process_id)
        )
        GetNamedPipeServerSessionId(
            self.__pipe_handle,
            ctypes.byref(server_session_id)
        )

        self.__debug('client process id: {0}', client_process_id.value)
        self.__debug('client session id: {0}', client_session_id.value)
        self.__debug('server process id: {0}', server_process_id.value)
        self.__debug('server session id: {0}', server_session_id.value)

        self.__reset_read()
        self.__read()
        self.__client_wait.set()


class Client(object):

    def __init__(self, pipe_name, packet_size=DEFAULT_PACKET_SIZE):
        self.__packet_size = packet_size
        self.__pipe_name = pipe_name
        self.__read_queue = None
        self.__pipe_handle = None
        self.__read_overlap = None
        self.__read_event = None
        self.__read_buffer = None
        self.__io_read = None
        self.__lock = None
        self.__io_event = None

    def __debug(self, msg, *args):

        msg = 'CLIENT: {0}: {1}'.format(self.__pipe_handle, msg)
        if args:
            msg = msg.format(*args)

        LOGGING.debug(msg)

    def open(self):
        if self.__pipe_handle is not None:
            raise PipeError('Client has already been opened.')
        self.__read_queue = queue.Queue()

        pipe_name = _create_pipe_name(self.__pipe_name)

        LOGGING.debug('CLIENT: opening {0}'.format(self.__pipe_name))

        while True:
            self.__pipe_handle = CreateFile(
                pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING,
                NULL
            )

            err = GetLastError()
            if err == ERROR_PIPE_BUSY:
                pass
            elif self.__pipe_handle != INVALID_HANDLE_VALUE:
                break

            elif not WaitNamedPipe(pipe_name, 2000):
                CloseHandle(self.__pipe_handle)
                self.__pipe_handle = None
                raise PipeError(err)

        self.__debug('pipe {0} opened', self.__pipe_name)
        client_process_id = ULONG(0)
        client_session_id = ULONG(0)
        server_process_id = ULONG(0)
        server_session_id = ULONG(0)

        GetNamedPipeClientProcessId(
            self.__pipe_handle,
            ctypes.byref(client_process_id)
        )
        GetNamedPipeClientSessionId(
            self.__pipe_handle,
            ctypes.byref(client_session_id)
        )
        GetNamedPipeServerProcessId(
            self.__pipe_handle,
            ctypes.byref(server_process_id)
        )
        GetNamedPipeServerSessionId(
            self.__pipe_handle,
            ctypes.byref(server_session_id)
        )

        self.__debug('client process id: {0}', client_process_id.value)
        self.__debug('client session id: {0}', client_session_id.value)
        self.__debug('server process id: {0}', server_process_id.value)
        self.__debug('server session id: {0}', server_session_id.value)

        self.__debug('setting pipe handle state')
        pipe_mode = DWORD(PIPE_READMODE_MESSAGE)

        result = SetNamedPipeHandleState(
            self.__pipe_handle,
            ctypes.byref(pipe_mode),
            NULL,
            NULL
        )

        if not result:
            err = GetLastError()
            CloseHandle(self.__pipe_handle)
            raise PipeError(err)

        self.__debug('IO thread start')
        self.__lock = threading.RLock()
        self.__io_event = threading.Event()
        self.__io_read = threading.Thread(
            name='Client Pipe {0} Read Worker'.format(str(self.__pipe_handle)),
            target=self.__read_loop
        )

        self.__io_read.daemon = True
        self.__io_read.start()

    @property
    def is_open(self):
        return not self.__io_event.isSet()

    def close(self):
        if self.__pipe_handle is None:
            raise PipeError(
                'You need to call open to open the client connection first'
            )

        self.__debug('closing')
        self.__io_event.set()
        self.__io_read.join(1.0)
        DisconnectNamedPipe(self.__pipe_handle)
        CloseHandle(self.__pipe_handle)
        self.__debug('closed')

        self.__pipe_handle = None
        CloseHandle(self.__read_event)

    @property
    def has_data(self):
        if self.__pipe_handle is None:
            raise PipeError(
                'You need to call open to open the client connection first'
            )
        return not self.__read_queue.empty()

    def read(self):
        if self.__pipe_handle is None:
            raise PipeError(
                'You need to call open to open the client connection first'
            )

        if not self.has_data:
            raise PipeError('No data available')
        try:
            return self.__read_queue.get()
        finally:
            self.__read_queue.task_done()

    def write(self, data, callback=None):
        guid = GUID()

        def do(write_data, write_callback, write_guid):

            self.__debug('creating write overlap event')
            write_overlap = OVERLAPPED()

            write_event = CreateEvent(
                NULL,
                True,
                False,
                NULL
            )

            if write_event == NULL:
                err = GetLastError()
                raise PipeError(err)

            write_overlap.hEvent = write_event

            if self.__write(write_data, write_overlap):
                CloseHandle(write_overlap.hEvent)
                if write_callback:
                    write_callback(write_guid)
            else:
                result = 0
                while not result:
                    write_bytes = DWORD(0)
                    result = GetOverlappedResult(
                        self.__pipe_handle,
                        ctypes.byref(write_overlap),
                        ctypes.byref(write_bytes),
                        True
                    )

                    err = GetLastError()
                    if result:
                        if write_bytes.value == len(write_data):
                            self.__debug('pending data written')
                            CloseHandle(write_overlap.hEvent)

                            if write_callback:
                                write_callback(write_guid)
                        else:
                            result = 0

                    elif err not in (
                        ERROR_IO_PENDING,
                        ERROR_IO_INCOMPLETE
                    ):
                        CloseHandle(write_overlap.hEvent)
                        raise PipeError(err)

                    ResetEvent(write_overlap.hEvent)

        t = threading.Thread(target=do, args=(data, callback, guid))
        t.daemon = True

        try:
            return guid
        finally:
            t.start()

    def __write(self, write_buffer, write_overlap):
        self.__debug('writing pipe')
        result = WriteFile(
            self.__pipe_handle,
            LPCSTR(write_buffer),
            len(write_buffer),
            NULL,
            ctypes.byref(write_overlap)
        )

        err = GetLastError()

        if result:
            self.__debug('data written')
            return False
        if err == ERROR_IO_PENDING:
            self.__debug('data pending write')
            return True
        elif err:
            try:
                raise PipeError(err)
            except PipeError:
                LOGGING.error(traceback.format_exc())
            return True

    def __reset_read(self):
        self.__debug('resetting read event')
        self.__read_overlap = OVERLAPPED()
        self.__read_event = CreateEvent(NULL, True, False, NULL)
        if self.__read_event == NULL:
            err = GetLastError()
            raise PipeError(err)

        self.__read_overlap.hEvent = self.__read_event
        self.__read_buffer = ctypes.create_string_buffer(self.__packet_size)

    def __read(self):
        self.__debug('reading pipe')
        result = ReadFile(
            self.__pipe_handle,
            self.__read_buffer,
            self.__packet_size,
            NULL,
            ctypes.byref(self.__read_overlap)
        )

        err = GetLastError()

        if result:
            self.__debug('data read')
            read_buffer = self.__read_buffer.value
            if read_buffer:
                self.__read_queue.put(read_buffer)
                self.__reset_read()
                return

        elif err != ERROR_IO_PENDING:
            raise PipeError(err)

        self.__debug('data pending read')

    def __read_loop(self):
        self.__debug('read thread started')
        self.__reset_read()
        while not self.__io_event.isSet():

            read_bytes = DWORD(0)
            result = GetOverlappedResult(
                self.__pipe_handle,
                ctypes.byref(self.__read_overlap),
                ctypes.byref(read_bytes),
                True
            )

            err = GetLastError()

            if result:
                if self.__read_buffer.value:
                    self.__debug('data read')
                    self.__read_queue.put(self.__read_buffer.value)

            elif err not in (ERROR_IO_PENDING, ERROR_IO_INCOMPLETE):
                if err == ERROR_BROKEN_PIPE:
                    return
                raise PipeError(err)

            self.__reset_read()
            self.__read()


class PipesContainer(object):
    __lock = threading.RLock()
    __pipes = []
    max_pipes = None

    def __init__(self, parent):
        self.__parent = parent

    def append(self,  p_object):
        with self.__lock:
            self.__pipes.append(p_object)

    def count(self, value):
        with self.__lock:
            return self.__pipes.count(value)

    def extend(self, iterable):
        with self.__lock:
            self.__pipes.extend(iterable)

    def index(self, value, start=None, stop=None):
        with self.__lock:
            return self.__pipes.index(value, start, stop)

    def insert(self, index,  p_object):
        with self.__lock:
            self.__pipes.insert(index, p_object)

    def pop(self, index=None):
        with self.__lock:
            return self.__pipes.pop(index)

    def remove(self, value):
        with self.__lock:
            self.__pipes.remove(value)

    def reverse(self):
        with self.__lock:
            self.__pipes.reverse()

    def sort(self, c=None, key=None,  reverse=False):
        with self.__lock:
            self.__pipes.sort(c, key, reverse)

    def __add__(self, y):
        return self.__pipes + y

    def __contains__(self, y):
        with self.__lock:
            return self.__pipes.__contains__(y)

    def __delitem__(self, y):
        with self.__lock:
            self.__pipes.__delitem__(y)

    def __delslice__(self, i,  j):
        with self.__lock:
            self.__pipes.__delslice__(i, j)

    def __eq__(self, y):
        return self.__pipes.__eq__(y)

    def __getitem__(self, y):
        with self.__lock:
            return self.__pipes.__getitem__(y)

    def __getslice__(self, i, j):
        with self.__lock:
            return self.__pipes.__getslice__(i, j)

    def __ge__(self, y):
        return self.__pipes.__ge__(y)

    def __gt__(self, y):
        return self.__pipes.__gt__(y)

    def __iadd__(self, y):
        with self.__lock:
            self.__pipes = self.__pipes.__iadd__(y)
        return self

    def __imul__(self, y):
        with self.__lock:
            self.__pipes = self.__pipes.__imul__(y)
        return self

    def purge(self):
        with self.__lock:
            no_clients = list(
                pipe_instance
                for pipe_instance in self.__pipes
                if not pipe_instance.has_client
            )

            short = True
            for pipe_instance in no_clients:
                if pipe_instance.has_client:
                    short = True
                else:
                    if short:
                        short = False
                    else:
                        pipe_instance.close()

            for pipe_instance in self.__pipes:
                if not pipe_instance.is_open and not pipe_instance.waiting_connection:
                    self.__pipes.remove(pipe_instance)
                    self.__parent.create_pipe_event.set()

            if self.max_pipes == PIPE_UNLIMITED_INSTANCES:
                to_many = 0
            else:
                to_many = len(self.__pipes) - self.max_pipes

            while to_many > 0:
                for pipe_instance in self.__pipes:
                    if not pipe_instance.has_client:
                        pipe_instance.close()
                        to_many -= 1
                        break
                else:
                    break

    def __iter__(self):
        with self.__lock:
            self.purge()
        return self.__pipes.__iter__()

    def __len__(self):
        with self.__lock:
            self.purge()
        return self.__pipes.__len__()

    def __le__(self, y):
        return self.__pipes.__le__(y)

    def __lt__(self, y):
        return self.__pipes.__lt__(y)

    def __mul__(self, n):
        return self.__pipes.__mul__(n)

    def __ne__(self, y):
        return self.__pipes.__ne__(y)

    def __repr__(self):
        return repr(self.__pipes)

    def __reversed__(self):
        return self.__pipes.__reversed__()

    def __rmul__(self, n):
        return self.__pipes.__rmul__(n)

    def __setitem__(self, i, y):
        with self.__lock:
            self.__pipes.__setitem__(i, y)

    def __setslice__(self, i, j, y):
        with self.__lock:
            self.__pipes.__setslice__(i, j, y)


class Server:

    def __init__(
        self,
        pipe_name,
        max_instances=DEFAULT_INSTANCES,
        time_out=DEFAULT_TIMEOUT,
        packet_size=DEFAULT_PACKET_SIZE,
        security=DEFAULT_SECURITY_ATTRIBUTES
    ):

        if max_instances == 0:
            raise PipeError(
                'Pipe max instances must be -1 for unlimited'
                ' or a value greater then 0'
            )

        elif max_instances == -1:
            max_instances = PIPE_UNLIMITED_INSTANCES

        self._thread = None
        self._pipes = PipesContainer(self)
        self._stopped = False
        self._event = threading.Event()
        self.create_pipe_event = threading.Event()
        self._pipe_name = pipe_name
        self._max_instances = max_instances
        self._time_out = time_out
        self._packet_size = packet_size
        self._security = security
        self._pipes.max_pipes = max_instances

    def __getitem__(self, item):
        try:
            return self._pipes[item]
        except IndexError:
            return None

    def __debug(self, msg, *args):

        msg = 'SERVER: {0}: {1}'.format(self._pipe_name, msg)
        if args:
            msg = msg.format(*args)

        LOGGING.debug(msg)

    def __iter__(self):
        for pipe_instance in self._pipes:
            if pipe_instance.has_client:
                yield pipe_instance

    def open(self):
        self.__debug('opening')

        if self._thread is None:
            self._thread = threading.Thread(
                name='{0} Named Pipe'.format(self._pipe_name),
                target=self.run
            )
            self._thread.start()

    def close(self):
        self.__debug('closing')
        self._event.set()
        self.create_pipe_event.set()
        self._thread.join(3.0)
        return self._stopped

    @property
    def max_instances(self):
        return (
            -1
            if self._max_instances == PIPE_UNLIMITED_INSTANCES
            else self._max_instances
        )

    @max_instances.setter
    def max_instances(self, value):
        if value == 0:
            raise PipeError(
                'Pipe max instances must be -1 for unlimited'
                ' or a value greater then 0'
            )

        elif value == -1:
            value = PIPE_UNLIMITED_INSTANCES

        self.__debug('new max instances: {0}', value)
        self._pipes.max_pipes = value
        self._max_instances = value

    @property
    def is_open(self):
        return not self._stopped

    def run(self):
        pipe_name = _create_pipe_name(self._pipe_name)
        if self._max_instances == PIPE_UNLIMITED_INSTANCES:
            max_instances = -1
        else:
            max_instances = self._max_instances

        while not self._event.isSet():
            for pipe_instance in self._pipes:
                if not pipe_instance.has_client:
                    break
            else:
                def open_pipe():
                    security_attributes = SECURITY_ATTRIBUTES()
                    security_descriptor = PSECURITY_DESCRIPTOR()

                    advapi32.SetSecurityDescriptorDacl(
                        ctypes.byref(security_descriptor),
                        BOOL(1),
                        NULL,
                        BOOL(0)
                    )

                    DEFAULT_SECURITY_ATTRIBUTES.lpSecurityDescriptor = (
                        security_descriptor
                    )
                    security_attributes.nLength = (
                        ctypes.sizeof(security_attributes)
                    )

                    if len(self._pipes) == 0:
                        self.__debug('creating pipe')
                        self.__debug('creating entry point')

                        pipe_handle = CreateNamedPipe(
                            pipe_name,
                            (
                                PIPE_ACCESS_DUPLEX |
                                FILE_FLAG_OVERLAPPED |
                                FILE_FLAG_FIRST_PIPE_INSTANCE
                            ),
                            (
                                PIPE_TYPE_MESSAGE |
                                PIPE_READMODE_MESSAGE |
                                PIPE_WAIT
                            ),
                            PIPE_UNLIMITED_INSTANCES,
                            self._packet_size,
                            self._packet_size,
                            self._time_out,
                            ctypes.byref(security_attributes)
                        )
                    else:
                        self.__debug('creating entry point')

                        pipe_handle = CreateNamedPipe(
                            pipe_name,
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                            (
                                PIPE_TYPE_MESSAGE |
                                PIPE_READMODE_MESSAGE |
                                PIPE_WAIT
                            ),
                            PIPE_UNLIMITED_INSTANCES,
                            self._packet_size,
                            self._packet_size,
                            self._time_out,
                            ctypes.byref(security_attributes)
                        )

                    err = GetLastError()

                    if err and err != ERROR_ALREADY_EXISTS:
                        DisconnectNamedPipe(pipe_handle)
                        CloseHandle(pipe_handle)
                        raise PipeError(err)

                    self.__debug('entry point {0} created', pipe_handle)
                    return pipe_handle

                if max_instances != -1 and len(self._pipes) == max_instances:
                    continue

                for pipe_instance in self._pipes:
                    if not pipe_instance.has_client:
                        break
                else:
                    handle = open_pipe()

                    if handle is None:
                        continue

                    pipe_instance = PipeInstance(
                        self._pipe_name,
                        handle,
                        self._packet_size
                    )
                    self._pipes.append(pipe_instance)

            self.create_pipe_event.clear()

        self._pipes.max_pipes = 0

        while len(self._pipes):
            continue

        self.__debug('closed')
        self._stopped = True


def send_single_message(pipe_name, msg, packet_size=DEFAULT_PACKET_SIZE):
    pipe_name = _create_pipe_name(pipe_name)
    while True:
        pipe_handle = CreateFile(
            pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        )
        if pipe_handle != INVALID_HANDLE_VALUE:
            break
        if GetLastError() != ERROR_PIPE_BUSY:
            pass
        elif WaitNamedPipe(pipe_name, 2000) == 0:
            CloseHandle(pipe_handle)
            return False

    pipe_mode = ULONG(PIPE_READMODE_MESSAGE)
    result = SetNamedPipeHandleState(
        pipe_handle,
        ctypes.byref(pipe_mode),
        NULL,
        NULL
    )

    if not result:
        err = GetLastError()
        CloseHandle(pipe_handle)
        if err:
            raise PipeError(err)
        else:
            raise PipeError(
                'send_single_message SetNamedPipeHandleState failed'
            )

    write_bytes = ULONG(0)

    while len(msg) != write_bytes.value:

        result = WriteFile(
            pipe_handle,
            LPCSTR(msg),
            len(msg),
            ctypes.byref(write_bytes),
            None
        )
        if not result:
            err = GetLastError()

            if err != ERROR_MORE_DATA:
                CloseHandle(pipe_handle)
                raise PipeError(err)

    result = 0
    read_buffer = ctypes.create_string_buffer(packet_size)
    read_bytes = ULONG(0)

    while not result:  # repeat loop if ERROR_MORE_DATA
        result = ReadFile(
            pipe_handle,
            read_buffer,
            packet_size,
            ctypes.byref(read_bytes),
            NULL
        )

        err = GetLastError()
        if err != ERROR_MORE_DATA:
            break

    CloseHandle(pipe_handle)
    return read_buffer.value


if __name__ == '__main__':
    import time
    LOGGING.logging = True

    server = Server('TestPipe', time_out=20000)
    LOGGING.debug('Opening Server')
    server.open()
    time.sleep(2.0)

    clients = {}
    client_event = threading.Event()
    stop_event = threading.Event()

    def go(index):
        client = Client('TestPipe')
        LOGGING.debug('    OPENING CLIENT ' + str(index))
        client.open()

        def get_client():
            for s_client in server:
                if s_client not in clients.values():
                    return s_client
            else:
                return get_client()

        clients[client] = get_client()
        client_event.set()
        evnt = threading.Event()

        def server_write_callback(id):
            LOGGING.debug('    SERVER: DATA WRITE CALLBACK: ' + str(id))

            while True:
                if client.has_data:
                    try:
                        in_data = client.read()
                    except PipeError as err:
                        if err[1] is not None:
                            raise err
                        continue

                    LOGGING.debug('    CLIENT {0}: DATA RECEIVED: '.format(index) + in_data)
                    if int(in_data.split(': ')[1]) == 9:
                        evnt.set()
                    break

        def client_write_callback(id):
            LOGGING.debug('    CLIENT {0}: DATA WRITE CALLBACK: '.format(index) + str(id))
            s_client = server[index]
            if s_client is None:
                return

            while True:
                while s_client.has_data:
                    try:
                        in_data = s_client.read()
                    except PipeError:
                        continue
                    LOGGING.debug('    SERVER: DATA RECEIVED: ' + in_data)
                    LOGGING.debug(
                        '    SERVER: WRITING DATA: ' + str(
                            s_client.write(
                                'This is server test data for client {0}: {1}'.format(index, in_data.split(': ')[1]),
                                server_write_callback
                            )
                        )
                    )
                if evnt.isSet():
                    break

        for i in range(10):
            LOGGING.debug(
                '    CLIENT {0}: WRITING DATA: '.format(index) + str(
                    client.write(
                        'This is client {0} test data: {1}'.format(index, i),
                        client_write_callback
                    )
                )
            )
        evnt.wait()

    connection = threading.Thread(target=go, args=(0,))
    connection.daemon = True
    connection.start()
    client_event.wait()
    go(1)

    for c in clients.keys():
        c.close()

    server.close()




