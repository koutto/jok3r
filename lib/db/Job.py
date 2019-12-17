#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Job
###
# Possible job status:
# - created
# - queued
# - running
# - finished_with_success
# - finished_with_error
# - stopped
# - aborted (ctrl+c during execution, hard kill of workers / docker stop...)
# - canceled
from sqlalchemy import ForeignKey, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method

from lib.db.Base import Base


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True)
    attack_profile = Column(String(255))
    checks_selection = Column(Text)
    categories_only = Column(String(255))
    categories_exclude = Column(String(255))
    nmap_banner_grabbing = Column(Boolean, default=False)
    web_techno_detection = Column(Boolean, default=False)
    force_recheck = Column(Boolean, default=False)
    debug_mode = Column(Boolean, default=False)
    fast_mode = Column(Boolean, default=True)
    wordlist_users = Column(String(255))
    wordlist_passwords = Column(String(255))
    wordlist_webpaths = Column(String(255))
    extra_options = Column(Text)
    status = Column(String(255))
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration = Column(Integer)
    worker_id = Column(Integer)
    exit_code = Column(Integer)
    comment = Column(Text, nullable=False, default="")
    service_id = Column(Integer, ForeignKey("services.id"))

    service = relationship("Service", back_populates="jobs")

    # ------------------------------------------------------------------------------------

    def __repr__(self):
        return (
            '<Job(id="{id}", '
            'attack_profile="{attack_profile}", '
            'checks_selection="{checks_selection}", '
            'categories_only="{categories_only}", '
            'categories_exclude="{categories_exclude}", '
            "nmap_banner_grabbing={nmap_banner_grabbing}, "
            "web_techno_detection={web_techno_detection}, "
            "force_recheck={force_recheck}, "
            "debug_mode={debug_mode}, "
            "fast_mode={fast_mode}, "
            'wordlist_users="{wordlist_users}", '
            'wordlist_passwords="{wordlist_passwords}", '
            'wordlist_webpaths="{wordlist_webpaths}", '
            'extra_options="{extra_options}", '
            'status="{status}", '
            'start_time="{start_time}", '
            'end_time="{end_time}", '
            "duration={duration}, "
            "worker_id={worker_id}, "
            "exit_code={exit_code}, "
            'comment="{comment}", '
            "target_service_id={target_service_id}".format(
                id=self.id,
                attack_profile=self.attack_profile,
                checks_selection=self.checks_selection,
                categories_only=self.categories_only,
                categories_exclude=self.categories_exclude,
                nmap_banner_grabbing=self.nmap_banner_grabbing,
                web_techno_detection=self.web_techno_detection,
                force_recheck=self.force_recheck,
                debug_mode=self.debug_mode,
                fast_mode=self.fast_mode,
                wordlist_users=self.wordlist_users,
                wordlist_passwords=self.wordlist_passwords,
                wordlist_webpaths=self.wordlist_webpaths,
                extra_options=self.extra_options,
                status=self.status,
                start_time=self.start_time,
                end_time=self.end_time,
                duration=self.duration,
                worker_id=self.worker_id,
                exit_code=self.exit_code,
                comment=self.comment,
                target_service_id=self.target_service_id,
            )
        )
