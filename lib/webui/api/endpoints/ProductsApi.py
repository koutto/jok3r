#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Products REST API
###
import io
from flask import request
from flask_restplus import Resource

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.ProductsRequester import ProductsRequester
from lib.webui.api.Api import api
from lib.webui.api.Models import Product
from lib.webui.api.Serializers import product


ns = api.namespace('products', description='Operations related to products')


@ns.route('/<int:id>')
class ProductAPI(Resource):

    @ns.doc('get_product')
    @ns.marshal_with(product)
    def get(self, id):
        """Return a product"""
        req = ProductsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.PRODUCT_ID))
        req.add_filter(filter_)
        p = req.get_first_result()
        if p:
            return Product(p)
        else:
            raise ApiNoResultFound()


    # @ns.doc('update_product')
    # @ns.expect(product)
    # @ns.marshal_with(product, code=201)
    # def put(self, id):
    #     """Update a product"""
    #     if 'comment' not in request.json:
    #         request.json['comment'] = ''

    #     req = ProductsRequester(Session)
    #     filter_ = Filter()
    #     filter_.add_condition(Condition(id, FilterData.VULN_ID))
    #     req.add_filter(filter_)
    #     v = req.get_first_result()   
    #     if v:
    #         if not req.edit_vuln_name(request.json['name']):
    #             raise ApiException('An error occured when trying to change ' \
    #                 'the name of the vulnerability')

    #         return Vuln(v)
    #     else:
    #         raise ApiNoResultFound()


    @ns.doc('delete_product')
    def delete(self, id):
        """Delete a vulnerability"""
        req = ProductsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(id, FilterData.PRODUCT_ID))
        req.add_filter(filter_)
        p = req.get_first_result()   
        if p:
            if req.delete():
                return None, 201
            else:
                raise ApiException('An error occured when trying to delete ' \
                    'product')
        else:
            raise ApiNoResultFound()     