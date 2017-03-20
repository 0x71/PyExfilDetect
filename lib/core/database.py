# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging
from time import time
import ConfigParser
import os
import json

try:
    from sqlalchemy import create_engine
    from sqlalchemy import ForeignKey
    from sqlalchemy.orm import sessionmaker, load_only, scoped_session
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, Integer, Float, String, Boolean
    from sqlalchemy.exc import IntegrityError, OperationalError
    from sqlalchemy.orm.exc import NoResultFound
    from sqlalchemy.ext import mutable
    from sqlalchemy import TypeDecorator
    from lib.common.constants import APP_ROOT

except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))

log = logging.getLogger(__name__)

cfg = ConfigParser.ConfigParser()
try:
    cfg.read(os.path.join(APP_ROOT, "conf", "database.conf"))
    conf_engine = cfg.get("connection","engine")

except:
    sys.exit("ERROR: Reading 'database.conf'")

engine = create_engine(conf_engine, echo=False)
#Session = sessionmaker(bind=engine)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)
#session = Session()

Base = declarative_base()

class JsonEncodedDict(TypeDecorator):
  """Enables JSON storage by encoding and decoding on the fly."""
  impl = String

  def process_bind_param(self, value, dialect):
    return json.dumps(value)

  def process_result_value(self, value, dialect):
    return json.loads(value)

mutable.MutableDict.associate_with(JsonEncodedDict)


class Database():
    def __init__(self):
        log.debug("Database started.")
        self.mysession = None
        self.hosts = []
        self.sessionhashosts = []

    def __del__(self):
        log.debug("Database stopped.")

    def createSession(self, start):
        session = Session()
        self.mysession = SniffSession(start,0)
        session.add(self.mysession)
        session.commit()
        session.close()

    def stopSession(self, stop):
        session = Session()
        session.query(SniffSession).filter_by(SessionID=self.mysession.SessionID).update({"EndTime": stop})
        session.commit()
        session.close()

    def addHost(self, ipaddr, identifier):
        try:
            session = Session()
            log.debug("ADDING HOST")
            self.hosts.append(SniffHost(ipaddr))
            session.add(self.hosts[-1])
            session.commit()
            log.debug("Host %s added." % ipaddr)
        except IntegrityError:
            log.debug("HOST ALREADY EXISTS.")
            session.rollback()

        host_id = self.addHostToSession(ipaddr, identifier, session)
        session.close()
        return host_id

    def addHostToSession(self, ipaddr, identifier, session):
        records = session.query(SniffHost).filter_by(IPAddr=ipaddr)
        host_id = records.one().HostID

        self.sessionhashosts.append(SessionHasHost(self.mysession.SessionID, host_id, identifier))
        session.add(self.sessionhashosts[-1])
        session.commit()

        return host_id

    def addStream(self, type):
        session = Session()
        records = session.query(SniffStream).filter_by(Type=type)
        try:
            stream_id = records.one().StreamID
            session.close()
            return stream_id
        except NoResultFound:
            mystream = SniffStream(type)
            session.add(mystream)
            session.commit()
            session.close()
            return mystream.StreamID

    def addStreamToHost(self, stream_id, host_id, identifier, first_timestamp):
        session = Session()
        stream_host = HostHasStream(self.mysession.SessionID, host_id, stream_id, identifier, first_timestamp)
        #print stream_host
        session.add(stream_host)
        session.commit()
        session.close()

    def getTasks(self):
        #retry = 3
        #for i in range(0,retry):
        try:
            session = Session()
            #session.commit()
            tasks = session.query(ExdeTask).filter_by(CurrentStatus=1)
            session.close()
            if len(tasks.all()) > 0:
                return tasks
            else:
                return None
        except OperationalError:
            log.error("MySQL timed out.")

        return None


    def getFileInfo(self, file_id):
        session = Session()
        files = session.query(ExdeFile).filter_by(FileID=file_id)
        session.close()
        try:
            if len(files.all()) > 0:
                return files
            else:
                return None
        except NoResultFound:
            log.error("No results found.")

    def setFilePackets(self, file_id, packet_count):
        session = Session()
        log.debug("[File %s] Updating packets." % file_id)
        session.query(ExdeFile).filter_by(FileID=file_id).update({"PacketCount": packet_count})
        session.commit()
        session.close()

    def setTaskStatus(self, task_id, status_id):
        session = Session()
        log.debug("[Task %s] Updating Status: %s." % (task_id, status_id))
        session.query(ExdeTask).filter_by(TaskID=task_id).update({"CurrentStatus": status_id})
        session.commit()
        session.close()

    def setTaskAnalysisResults(self, task_id, analysis_id):
        session = Session()
        log.info("[Task %s] Updating AnalysisResults: %s." % (task_id, analysis_id))
        session.query(ExdeTask).filter_by(TaskID=task_id).update({"AnalysisResults": analysis_id})
        session.commit()
        session.close()

class ExdeFile(Base):
    __tablename__ = "exde_file"

    FileID = Column(Integer, primary_key=True, autoincrement=True)
    Name = Column(String)
    OrigName = Column(String)
    Extension = Column(String)
    Size = Column(Integer)
    Path = Column(String)
    Hash = Column(String)
    PacketCount = Column(Integer)

    def __init__(self):
        pass

    def __repr__(self):
        return "<ExdeFile(%s, %s, %s)>" % (self.FileID, self.Name, self.Path)

class ExdeTask(Base):
    __tablename__ = "exde_task"
    #SessionID = Column(Integer, ForeignKey('SniffSession.SessionID'), primary_key=True)

    TaskID = Column(Integer, primary_key=True, autoincrement=True)
    UserID = Column(Integer, ForeignKey('exde_user.UserID'))
    FileID = Column(Integer, ForeignKey('exde_file.FileID'))
    Date = Column(Float)
    AnalysisResults = Column(Integer)
    Public = Column(Boolean)
    CurrentStatus = Column(Integer)

    def __init__(self):
        pass

    def __repr__(self):
        return "<ExdeTask(%s, %s, %s)>" % (self.TaskID, self.UserID, self.FileID)

class SniffSession(Base):
    __tablename__ = "SniffSession"

    SessionID = Column(Integer, primary_key=True, autoincrement=True)
    StartTime = Column(Float)
    EndTime = Column(Float)

    def __init__(self, start=0, end=0):
        self.StartTime = start
        self.EndTime = end

    def __repr__(self):
        return "<SniffSession(%s, %s, %s)>" % (self.SessionID, self.StartTime, self.EndTime)

class SniffHost(Base):
    __tablename__ = "SniffHost"

    HostID = Column(Integer, primary_key=True, autoincrement=True)
    IPAddr = Column(String(45))

    def __init__(self, ipaddr=0):
        self.IPAddr = ipaddr

    def __repr__(self):
        return "<SniffHost(%s, %s, %s)>" % (self.HostID, self.IPAddr)

class SessionHasHost(Base):
    __tablename__ = "SniffSession_has_SniffHost"

    SessionID = Column(Integer, ForeignKey('SniffSession.SessionID'), primary_key=True)
    HostID = Column(Integer, ForeignKey('SniffHost.HostID'), primary_key=True)
    DisplayHostID = Column(Integer, unique=True)

    def __init__(self, session_id, host_id, display_id):
        self.SessionID = session_id
        self.HostID = host_id
        self.DisplayHostID = display_id

    def __repr__(self):
        return "<SessionHasHost(%s, %s, %s)>" % (self.SessionID, self.HostID, self.DisplayHostID)

class SniffStream(Base):
    __tablename__ = "SniffStream"

    StreamID = Column(Integer, primary_key=True, autoincrement=True)
    Type = Column(String(10), unique=True)

    def __init__(self,  type):
        self.Type = type

    def __repr__(self):
        return "<SniffStream(%s, %s, %s)>" % (self.SessionID, self.Type)

class HostHasStream(Base):
    __tablename__ = "SniffSession_has_SniffHost_has_SniffStream"

    SessionID = Column(Integer, ForeignKey('SniffSession_has_SniffHost.SessionID'), primary_key=True)
    HostID = Column(Integer, ForeignKey('SniffSession_has_SniffHost.HostID'), primary_key=True)
    StreamID = Column(Integer, ForeignKey('SniffStream.StreamID'), primary_key=True)
    LocalStreamID = Column(Integer, primary_key=True)
    StartTime = Column(Float)

    def __init__(self, session_id, host_id, stream_id, local_id, start):
        self.SessionID = session_id
        self.HostID = host_id
        self.StreamID = stream_id
        self.LocalStreamID = local_id
        self.StartTime = start

    def __repr__(self):
        return "<HostHasStream(%s, %s, %s, %s, %s)>" % (self.SessionID, self.HostID, self.StreamID, self.LocalStreamID, self.StartTime)
