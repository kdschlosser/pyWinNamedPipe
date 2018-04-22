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

try:
    # noinspection PyPep8Naming
    import Queue as queue
except ImportError:
    import queue

from ctypes.wintypes import (
    HANDLE,
    ULONG,
    LPCSTR,
    DWORD,
    WORD,
    BOOL,
    BYTE,
)

# various c types that get used when passing data to the Windows functions
PVOID = ctypes.c_void_p
UCHAR = ctypes.c_ubyte
ULONG_PTR = ctypes.POINTER(ULONG)
NULL = None

# returned values for kernel32.WaitForSingleObject
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF

# can be passed to kernel32.WaitForSingleObject
INFINITE = 0xFFFFFFFF

# bit identifiers for the pipe type, used in kernel32.CreateNamedPipeA
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

FILE_FLAG_OVERLAPPED = 0x40000000
FILE_ATTRIBUTE_NORMAL = 0x00000080

FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000

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
ERROR_ALREADY_EXISTS = 0x000000B6
ERROR_ACCESS_DENIED = 0x00000005
ERROR_IO_PENDING = 0x000003E5
INVALID_HANDLE_VALUE = -1

# bit identifiers passed to kernel32.FormatMessageA located in PipeError
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


# a single Exception class that handles all pipe errors. This queries Windows
# for an error message if an error code was supplied otherwise it will use the
# string that has been passed to it. You can check the error code by doing the
# following
#
# try:
#     # do pipe code here
# except PipeError as err:
#     print err[1]
#
# the above will print out None if it is an error that does not have a code
# passed otherwise it will print out a decimal version of the windows error
# code

class LOGGING:

    @staticmethod
    def debug(data):
        sys.stdout.write(data + '\n')

    @staticmethod
    def error(data):
        sys.stderr.write(data + '\n')


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
    pipe_handle = kernel32.CreateNamedPipeA(
        _create_pipe_name(name),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        DEFAULT_PACKET_SIZE,
        DEFAULT_PACKET_SIZE,
        50,
        NULL
    )
    err = kernel32.GetLastError()
    kernel32.CloseHandle(pipe_handle)

    if err:
        return True

    return False


# the main handler for a pipe connection.
class PipeInstance(object):

    def __init__(self, pipe_name, pipe_handle, packet_size):
        self._pipe_name = pipe_name
        self._pipe_handle = pipe_handle
        self._packet_size = packet_size

        self._write_queue = queue.Queue()
        self._write_io = []

        self._read_queue = queue.Queue()
        self._read_overlap = None
        self._read_event = None
        self._read_buffer = None

        # create an instance os the overlapped io structure
        self._client_overlap = OVERLAPPED()

        # get an event handle from Windows
        self._client_event = kernel32.CreateEventA(
            NULL,  # default security attribute
            True,  # manual-reset event
            False,  # initial state
            NULL  # unnamed event object
        )

        # if for some reason Windows is not able to give us an event handle
        # stop everything right there
        if self._client_event == NULL:
            err = kernel32.GetLastError()
            raise PipeError(err)

        # set the event handle into the overlapped io instance
        self._client_overlap.hEvent = self._client_event

        # if a client is connected to the pipe
        self.has_client = False
        self._pending_connection = False

        # threading bits
        self.__lock = threading.RLock()
        self.__io_event = threading.Event()
        self.__io_thread = threading.Thread(
            name='Named Pipe {0} IO Worker'.format(str(pipe_handle)),
            target=self.__io
        )

        # even tho there is a shutdown procedure for the pipe we still want to
        # end the thread that controls the pipe in the event the main process
        # terminates without running the shutdown procedure
        self.__io_thread.daemon = True
        self.__io_thread.start()

    # since creating a closing pipe instances takes time to do, we only do it
    # once.
    # so to keep performance boosted as the cost of a very small amount of
    # memory use we reuse the pipe when the client disconnects or an error
    # takes place
    def reconnect(self):
        with self.__lock:
            # this disconnects the client end of the pipe it does not close the
            # pipe
            kernel32.DisconnectNamedPipe(self._pipe_handle)
            # reset data storage containers
            self._write_queue = queue.Queue()
            self._write_io = []

            self._read_queue = queue.Queue()
            self._read_overlap = None
            self._read_event = None
            self._read_buffer = None

            kernel32.ResetEvent(self._client_event)
            self.has_client = False
            self._pending_connection = False

    # if the pipe is open or closed. closed means a client can no longer
    # connect to this pipe instance
    @property
    def is_open(self):
        return not self.__io_event.isSet()

    # closes the pipe instance
    def close(self):
        LOGGING.debug(
            'Closing pipe ' + str(self._pipe_handle)
        )
        self.__io_event.set()

        if threading.currentThread() != self.__io_thread:
            # if not self.has_client:
            #     try:
            #         send_single_message(
            #             self._pipe_name,
            #             'stop_pipe',
            #             self._packet_size
            #         )
            #     except PipeError:
            #         pass
            self.__io_thread.join(1.0)

    @property
    def has_data(self):
        return not self._read_queue.empty()

    def read(self):
        if not self.has_data:
            raise PipeError('No data available')
        try:
            return self._read_queue.get()
        finally:
            self._read_queue.task_done()

    def write(self, data):
        self._write_queue.put(data)

    def __write(self, write_buffer, write_overlap):
        self.pending_io = True

        result = kernel32.WriteFile(
            self._pipe_handle,
            LPCSTR(write_buffer),
            len(write_buffer),
            NULL,
            ctypes.byref(write_overlap)
        )

        err = kernel32.GetLastError()

        if result:
            return False
        if err == ERROR_IO_PENDING:
            return True
        elif err:
            LOGGING.error(traceback.format_exc())
            self.reconnect()
            return True

    def _reset_read(self):
        self._read_overlap = OVERLAPPED()
        self._read_event = kernel32.CreateEventA(NULL, True, False, NULL)
        if self._read_event == NULL:
            err = kernel32.GetLastError()
            raise PipeError(err)

        self._read_overlap.hEvent = self._read_event
        self._read_buffer = ctypes.create_string_buffer(self._packet_size)

    def __read(self):
        result = kernel32.ReadFile(
            self._pipe_handle,
            self._read_buffer,
            self._packet_size,
            NULL,
            ctypes.byref(self._read_overlap)
        )

        err = kernel32.GetLastError()

        if result:
            read_buffer = self._read_buffer.value
            if read_buffer:
                if read_buffer == 'stop_pipe':
                    self.close()
                else:
                    self._read_queue.put(read_buffer)
                    self._reset_read()

        elif err == ERROR_IO_PENDING:
            pass

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

    def __io(self):
        while not self.__io_event.isSet():
            if not self.has_client and not self._pending_connection:
                self._pending_connection = not self.connect()

                if not self._pending_connection:
                    LOGGING.debug(
                        'Named pipe {0} connected'.format(
                            str(self._pipe_handle))
                    )
            elif not self.has_client and self._pending_connection:
                result = kernel32.WaitForSingleObject(
                    self._pipe_handle,
                    50
                )

                if result == WAIT_TIMEOUT:
                    continue

                if result in (WAIT_ABANDONED, WAIT_FAILED):
                    err = kernel32.GetLastError()
                    try:
                        raise PipeError(err)
                    except PipeError:
                        LOGGING.error(traceback.format_exc())
                        self.reconnect()
                        continue

                LOGGING.debug(
                    'Named pipe {0} connected'.format(
                        str(self._pipe_handle))
                )
                self._pending_connection = False
                self.has_client = True
                self._reset_read()
                self.__read()

            if self.has_client:
                with self.__lock:
                    result = kernel32.WaitForSingleObject(
                        self._pipe_handle,
                        50
                    )

                    if result == WAIT_TIMEOUT:
                        continue

                    if result in (WAIT_ABANDONED, WAIT_FAILED):
                        err = kernel32.GetLastError()
                        try:
                            raise PipeError(err)
                        except PipeError:
                            LOGGING.error(traceback.format_exc())
                            self.reconnect()
                            continue

                    LOGGING.debug(
                        'Named pipe {0} incoming event'.format(
                            str(self._pipe_handle)
                        )
                    )

                    read_bytes = ULONG(0)

                    # result = kernel32.GetOverlappedResult(
                    #     handle to pipe,
                    #     ctypes.byref(# OVERLAPPED structure),
                    #     bytes transferred,
                    #     do not wait
                    # )

                    result = kernel32.GetOverlappedResult(
                        self._pipe_handle,
                        ctypes.byref(self._read_overlap),
                        ctypes.byref(read_bytes),
                        False
                    )

                    err = kernel32.GetLastError()

                    if result:
                        if read_bytes.value != 0:
                            if self._read_buffer.value == 'stop_pipe':
                                self.close()
                                return

                            self._read_queue.put(self._read_buffer.value)
                            self._reset_read()
                            self.__read()

                    elif err != ERROR_IO_PENDING:
                        try:
                            raise PipeError(err)
                        except PipeError:
                            LOGGING.error(traceback.format_exc())
                            self.reconnect()
                            continue

                    for write_buffer, write_overlapped in self._write_io:
                        write_bytes = ULONG(0)
                        result = kernel32.GetOverlappedResult(
                            self._pipe_handle,
                            ctypes.byref(write_overlapped),
                            ctypes.byref(write_bytes),
                            False
                        )

                        err = kernel32.GetLastError()

                        if result:
                            if write_bytes.value == len(write_buffer):
                                self._write_io.remove(
                                    (write_buffer, write_overlapped)
                                )
                            else:
                                self._write_queue.put(write_buffer)

                        elif err != ERROR_IO_PENDING:
                            try:
                                raise PipeError(err)
                            except PipeError:
                                LOGGING.error(traceback.format_exc())
                                self.reconnect()
                                continue

                        if not self._write_queue.empty():
                            write_buffer = self._write_queue.get()
                            self._write_queue.task_done()

                            write_overlap = OVERLAPPED()
                            write_event = kernel32.CreateEventA(
                                NULL,
                                True,
                                False,
                                NULL
                            )

                            if write_event == NULL:
                                err = kernel32.GetLastError()
                                raise PipeError(err)

                            write_overlap.hEvent = write_event

                            if self.__write(write_buffer, write_overlap):
                                self._write_io.append(
                                    (write_buffer, write_overlap)
                                )

        kernel32.FlushFileBuffers(self._pipe_handle)
        kernel32.DisconnectNamedPipe(self._pipe_handle)
        kernel32.CloseHandle(self._pipe_handle)

    def connect(self):
        LOGGING.debug('Connecting named pipe')

        result = kernel32.ConnectNamedPipe(
            self._pipe_handle,
            ctypes.byref(self._client_overlap)
        )
        err = kernel32.GetLastError()

        if result:
            self.has_client = True

        elif err == ERROR_IO_PENDING:
            self.has_client = False

        elif err == ERROR_PIPE_CONNECTED:
            self.has_client = True

        elif err:
            try:
                raise PipeError(err)
            except PipeError:
                LOGGING.error(traceback.format_exc())

            self.reconnect()

        return self.has_client


# container object that holds the pipe instances. This container checks for
# closed pipes and removes them. it also checks to see if eg.config.maxPipes
# has changed and if the number is now lower it will close any pipes that are
# not connected to a client. it will do this each time the container is
# accessed until the number of pipe instances matches eg.config.maxPipes
class PipesContainer(object):
    __lock = threading.RLock()
    __pipes = []
    max_pipes = None

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
                if not pipe_instance.is_open:
                    self.__pipes.remove(pipe_instance)

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
        self._pipes = PipesContainer()
        self._stopped = False
        self._event = threading.Event()
        self._pipe_name = pipe_name
        self._max_instances = max_instances
        self._time_out = time_out
        self._packet_size = packet_size
        self._security = security
        self._pipes.max_pipes = max_instances

    def __iter__(self):
        for pipe_instance in self._pipes:
            if pipe_instance.has_client:
                yield pipe_instance

    def open(self):
        if self._thread is None:
            self._thread = threading.Thread(
                name='{0} Named Pipe'.format(self._pipe_name),
                target=self.run
            )
            self._thread.start()

    def close(self):
        self._event.set()
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
                    LOGGING.debug('Creating named pipe')
                    if len(self._pipes) == 0:
                        pipe_handle = kernel32.CreateNamedPipeA(
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
                            ctypes.byref(self._security)
                        )
                    else:
                        pipe_handle = kernel32.CreateNamedPipeA(
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
                            ctypes.byref(self._security)
                        )

                    if pipe_handle == INVALID_HANDLE_VALUE:
                        err = kernel32.GetLastError()

                        kernel32.DisconnectNamedPipe(pipe_handle)
                        kernel32.CloseHandle(pipe_handle)
                        if err:
                            raise PipeError(err)
                        else:
                            raise PipeError('Unable to create named pipe')

                    return pipe_handle
                if max_instances != -1 and len(self._pipes) == max_instances:
                    continue

                for pipe_instance in self._pipes:
                    if not pipe_instance.has_client:
                        break
                else:
                    handle = open_pipe()

                    pipe_instance = PipeInstance(
                        self._pipe_name,
                        handle,
                        self._packet_size
                    )
                    self._pipes.append(pipe_instance)

            self._event.wait(0.2)

        LOGGING.debug('Closing named pipe')

        while self._pipes:
            pipe_instance = self._pipes.pop(0)
            if not pipe_instance.is_open:
                continue
            pipe_instance.close()

        LOGGING.debug('Named pipe is closed')
        self._stopped = True


class Client(object):

    def __init__(self, pipe_name, packet_size=DEFAULT_PACKET_SIZE):
        self._packet_size = packet_size
        self._pipe_name = pipe_name
        self._read_queue = None
        self._write_queue = None
        self.__read_event = None
        self.__write_event = None
        self.__read_thread = None
        self.__write_thread = None
        self._pipe_handle = None

    def open(self):
        self._read_queue = queue.Queue()
        self._write_queue = queue.Queue()
        self.__read_event = threading.Event()
        self.__write_event = threading.Event()
        self.__read_thread = threading.Thread(
            name='Client Pipe {0} Read'.format(self._pipe_name),
            target=self.__read
        )
        self.__write_thread = threading.Thread(
            name='Client Pipe {0} Write'.format(self._pipe_name),
            target=self.__write
        )
        self.__read_thread.daemon = True
        self.__write_thread.daemon = True

        pipe_name = _create_pipe_name(self._pipe_name)

        while True:
            self._pipe_handle = kernel32.CreateFileA(
                pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            )

            err = kernel32.GetLastError()

            if self._pipe_handle != INVALID_HANDLE_VALUE:
                break
            if err == ERROR_PIPE_BUSY:
                pass
            elif not kernel32.WaitNamedPipeA(pipe_name, 2000):
                kernel32.CloseHandle(self._pipe_handle)
                self._pipe_handle = None
                raise PipeError(err)

        pipe_mode = ULONG(PIPE_READMODE_MESSAGE)

        result = kernel32.SetNamedPipeHandleState(
            self._pipe_handle,
            ctypes.byref(pipe_mode),
            NULL,
            NULL
        )

        if not result:
            err = kernel32.GetLastError()
            kernel32.CloseHandle(self._pipe_handle)
            self._pipe_handle = None
            if err:
                raise PipeError(err)
            else:
                raise PipeError(
                    'send_single_message SetNamedPipeHandleState failed'
                )

        self.__read_thread.start()
        self.__write_thread.start()

    def __write(self):
        while not self.__write_event.isSet():
            if not self._write_queue.empty():
                write_buffer = self._write_queue.get()

                write_bytes = ULONG(0)
                while len(write_buffer) != write_bytes.value:
                    result = kernel32.WriteFile(
                        self._pipe_handle,
                        LPCSTR(write_buffer),
                        len(write_buffer),
                        ctypes.byref(write_bytes),
                        None
                    )
                    if not result:
                        err = kernel32.GetLastError()

                        if err != ERROR_MORE_DATA:
                            kernel32.CloseHandle(self._pipe_handle)
                            raise PipeError(err)

                self._write_queue.task_done()

    def __read(self):
        while not self.__read_event.isSet():
            result = 0
            read_buffer = ctypes.create_string_buffer(self._packet_size)
            read_bytes = ULONG(0)

            while not result:  # repeat loop if ERROR_MORE_DATA
                result = kernel32.ReadFile(
                    self._pipe_handle,
                    read_buffer,
                    self._packet_size,
                    ctypes.byref(read_bytes),
                    NULL
                )

                err = kernel32.GetLastError()
                if err != ERROR_MORE_DATA:
                    break
            if read_bytes.value != 0:
                self._read_queue.put(read_buffer.value)

    def write(self, data):
        if self._pipe_handle is None:
            raise PipeError(
                'You need to call open to open he client connection first'
            )
        self._write_queue.put(data)

    @property
    def has_data(self):
        return not self._read_queue.empty()

    def read(self):
        if self._pipe_handle is None:
            raise PipeError(
                'You need to call open to open he client connection first'
            )
        if self._read_queue.empty():
            raise PipeError('Read buffer is empty')
        try:
            return self._read_queue.get()
        finally:
            self._read_queue.task_done()

    def close(self):
        if self._pipe_handle is None:
            raise PipeError(
                'You need to call open to open he client connection first'
            )
        self.__read_event.set()
        self.__write_event.set()

        kernel32.CloseHandle(self._pipe_handle)
        self.__write_thread.join()
        self.__read_thread.join()


def send_single_message(pipe_name, msg, packet_size=DEFAULT_PACKET_SIZE):
    pipe_name = _create_pipe_name(pipe_name)
    while True:
        pipe_handle = kernel32.CreateFileA(
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
        if kernel32.GetLastError() != ERROR_PIPE_BUSY:
            pass
        elif kernel32.WaitNamedPipeA(pipe_name, 2000) == 0:
            kernel32.CloseHandle(pipe_handle)
            return False

    pipe_mode = ULONG(PIPE_READMODE_MESSAGE)
    result = kernel32.SetNamedPipeHandleState(
        pipe_handle,
        ctypes.byref(pipe_mode),
        NULL,
        NULL
    )

    if not result:
        err = kernel32.GetLastError()
        kernel32.CloseHandle(pipe_handle)
        if err:
            raise PipeError(err)
        else:
            raise PipeError(
                'send_single_message SetNamedPipeHandleState failed'
            )

    write_bytes = ULONG(0)

    while len(msg) != write_bytes.value:

        result = kernel32.WriteFile(
            pipe_handle,
            LPCSTR(msg),
            len(msg),
            ctypes.byref(write_bytes),
            None
        )
        if not result:
            err = kernel32.GetLastError()

            if err != ERROR_MORE_DATA:
                kernel32.CloseHandle(pipe_handle)
                raise PipeError(err)

    result = 0
    read_buffer = ctypes.create_string_buffer(packet_size)
    read_bytes = ULONG(0)

    while not result:  # repeat loop if ERROR_MORE_DATA
        result = kernel32.ReadFile(
            pipe_handle,
            read_buffer,
            packet_size,
            ctypes.byref(read_bytes),
            NULL
        )

        err = kernel32.GetLastError()
        if err != ERROR_MORE_DATA:
            break

    kernel32.CloseHandle(pipe_handle)
    return read_buffer.value


if __name__ == '__main__':
    server = Server('TestPipe')
    client = Client('TestPipe')

    server.open()
    client.open()

    client.write('This is client test data')

    while True:
        for s_client in server:
            if s_client.has_data:
                print s_client.read()
                s_client.write('This is server test data')
                break
        else:
            continue
        break

    while True:
        if client.has_data:
            print client.read()
            break
