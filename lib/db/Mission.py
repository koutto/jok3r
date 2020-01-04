#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Db > Mission
###
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_method
from sqlalchemy.sql import func

from lib.db.Base import Base
from lib.db.Host import Host


class Mission(Base):
    __tablename__ = 'missions'

    id            = Column(Integer, primary_key=True)
    name          = Column(String(255), nullable=False, default='')
    comment       = Column(String(255), nullable=False, default='')
    creation_date = Column(DateTime, default=func.now())
    notes         = Column(Text)

    hosts         = relationship('Host', order_by=Host.id, back_populates='mission',
        cascade='save-update, merge, delete, delete-orphan')


    #------------------------------------------------------------------------------------

    @hybrid_method
    def get_nb_services(self):
        """Return the total number of services inside the mission scope"""
        nb = 0
        for host in self.hosts:
            nb += len(host.services)
        return nb


    @hybrid_method
    def get_nb_credentials(self, single_username=False):
        """
        Get total number of credentials for all services referenced for this mission.
        :param bool single_username: If True, get the number of single usernames 
            (password unknown). If False, get the number of username/password couples
        :return: Number of selected credentials
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_credentials(single_username)
        return nb


    @hybrid_method
    def get_nb_products(self):
        """
        Get total number of detected products for all services referenced for 
        this mission.
        :return: Number of detected products
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_products()
        return nb


    @hybrid_method
    def get_nb_vulns(self):
        """
        Get total number of detected vulns for all services referenced for 
        this mission.
        :return: Number of detected vulns
        :rtype: int
        """
        nb = 0
        for h in self.hosts:
            nb += h.get_nb_vulns()
        return nb


    @hybrid_method
    def get_checks_categories(self):
        """
        Get list of categories of checks that have been partially or fully run for the
        mission.
        Note: If only one single check in a category (e.g. recon) has been run for the
        mission, it is returned.

        :return: List of categories of checks with counts
        :rtype: list({'name': str, 'count': int)
        """
        categories = list()
        for host in self.hosts:
            for service in host.services:
                for res in service.results:
                    found = False
                    for cat in categories:
                        if res.category == cat['name']:
                            cat['count'] += 1
                            found = True
                            break
                    if not found:
                        categories.append({
                            'name': res.category,
                            'count': 1,
                        })

        return categories


    @hybrid_method
    def get_nb_services_repartition(self):
        """
        Get count of each service name in the mission.

        :return: List of service names with counts
        :rtype: list({'name': str, 'count': int})
        """
        nb_services = list()
        for host in self.hosts:
            for service in host.services:
                found = False
                for s in nb_services:
                    if service.name == s['name']:
                        s['count'] += 1
                        found = True
                        break
                if not found:
                    nb_services.append({
                        'name': service.name,
                        'count': 1
                    })

        return nb_services


    @hybrid_method
    def get_nb_products_repartition(self):
        """
        Get count of each product name and OS family in the mission.

        :return: List of product names and OS families with counts
        :rtype: list({'name': str, 'count': int'})
        """
        nb_products = list()
        for host in self.hosts:
            for service in host.services:
                for product in service.products:
                    found = False
                    for p in nb_products:
                        if product.name == p['name']:
                            p['count'] += 1
                            found = True
                            break
                    if not found:
                        nb_products.append({
                            'name': product.name,
                            'count': 1
                        })

            found = False
            for p in nb_products:
                if host.os_family == p['name']:
                    p['count'] += 1
                    found = True
                    break
            if not found:
                nb_products.append({
                    'name': host.os_family,
                    'count': 1
                })

        return nb_products

    @hybrid_method
    def get_nb_vulns_repartition(self):
        """
        Get count of each vulnerability level: 
            undefined, low, medium, high, critical

        :return: Number of vulnerabilities for each level (from undefined to critical)
        :rtype: list(int)
        """
        nb_vulns = [0, 0, 0, 0, 0]
        for host in self.hosts:
            for service in host.services:
                for vuln in service.vulns:
                    if vuln.score is None:
                        nb_vulns[0] += 1
                    elif vuln.score < 3:
                        nb_vulns[1] += 1
                    elif vuln.score <= 5:
                        nb_vulns[2] += 1
                    elif vuln.score < 7.5:
                        nb_vulns[3] += 1
                    else:
                        nb_vulns[4] += 1
        return nb_vulns

    #------------------------------------------------------------------------------------
            
    def __repr__(self):
        return '<Mission(name="{name}", comment="{comment}", ' \
            'creation_date="{creation_date}")>'.format(
                name          = self.name,
                comment       = self.comment,
                creation_date = self.creation_date)

