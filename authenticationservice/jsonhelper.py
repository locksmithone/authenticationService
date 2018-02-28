# -*- coding: utf-8 -*-
"""
Created on Thu Jun 11 14:01:55 2015

@author: locksmith
"""

import time
import calendar
import charm.core.math.pairing
import charm.toolbox.pairinggroup
import base64
import json

def deserialize_from_json(json_object, param=None):  
    """
    Deserialize undefined objects from JSON format.
    """
    
    #print (json_object)
    if '__class__' in json_object:                            
        if json_object['__class__'] == 'time.asctime':
            return time.strptime(json_object['__value__'])    
        if json_object['__class__'] == 'bytes':
            return bytes(base64.b64decode(json_object['__value__']))   
        if json_object['__class__'] == 'pairing.Element' and 'param' in kwargs:
            # Create a PairingGroup object from param args[0] such that we can utilize the deserialize method.
            groupObj = charm.toolbox.pairinggroup.PairingGroup(kwargs['param'])            
            #print(json_object['__value__'].encode())
            #print(type(json_object['__value__'].encode()))
            return groupObj.deserialize(json_object['__value__'].encode())
            
            
#==============================================================================
#             class ComplexEncoder(json.JSONEncoder):
# ...     def default(self, obj):
# ...         if isinstance(obj, complex):
# ...             return [obj.real, obj.imag]
# ...         # Let the base class default method raise the TypeError
# ...         return json.JSONEncoder.default(self, obj)
#==============================================================================
            
    """
    This is how we convert a time in list format to a time.struct_time.
    1. Convert the list to a tuple.
    2. Use calendar.timegm to convert the tuple into Unix timestamp value UTC.
    3. Use time.gmtime to conver it into time.struct_time.
    """
    if 'published_date' in json_object:
        json_object['published_date'] = time.gmtime(calendar.timegm(tuple(json_object['published_date'])))
        #return json_object
        #return time.gmtime(calendar.timegm(tuple(json_object['published_date'])))
    if 'updated' in json_object:
        json_object['updated'] = time.gmtime(calendar.timegm(tuple(json_object['updated'])))
        #return json_object
    return json_object
    
    
class KeyDecoder(json.JSONDecoder):
    
    def __init__(self):
        json.JSONDecoder.__init__(self, object_hook=self.deserializeFromJson)

    def deserializeFromJson(self, jsonObject):
        if '__class__' in jsonObject:
            if jsonObject['__class__'] == 'time.asctime':
                return time.strptime(jsonObject['__value__'])    
            if jsonObject['__class__'] == 'bytes':
                return bytes(base64.b64decode(jsonObject['__value__']))   
            if jsonObject['__class__'] == 'pairing.Element':
                # Create a PairingGroup object from param args[0] such that we can utilize the deserialize method.
                groupObj = charm.toolbox.pairinggroup.PairingGroup(jsonObject['__pairingCurve__'])            
                #print(jsonObject['__value__'].encode())
                #print(type(jsonObject['__value__'].encode()))
                return groupObj.deserialize(jsonObject['__value__'].encode())            
                
#            class_name = jsonObject.pop('__class__')
#            module_name = jsonObject.pop('__module__')
#            module = __import__(module_name)
#            class_ = getattr(module, class_name)
#            args = dict( (key.encode('ascii'), value) for key, value in jsonObject.items())
#            inst = class_(**args)
        else:
            inst = jsonObject
        return inst


class KeyEncoder(json.JSONEncoder):
    """
    Serialize undefined JSON types, in particular pairing.Element objects within Charm keys.
    
    The goal of this class is to convert Python objects/types that JSON does not recognize to dictionaries with enough
    information such as to convert the dictionaries back to native Python objects. In particular, Charm Crypto
    utilizes pairing.Element types to represent several keys, wherein the pairing.Element are elements in some
    pairing group or, in addition, ellyptic curve. The pairing.Element might consist of one large number, or a list of
    two numbers (X and Y coordinates in a curve). JSON cannot understand this pairing.Element type and thus we must
    convert it to some dictionary such that JSON can serialize it. We may need, however, additional information not contained
    within the Python objects themselves, as we explain below.
    
    The strategy is to utilize the serialize and deserialize methods in charm.toolbox.pairinggroup, that in themselves
    utilize the serialize/deserialize functions from PBC.
    
    The serialize method needs nothing but the pairing.Element object to serialize, and produces a byte
    representation of the pairing.Element in base64. To pass it to JSON, we decode the bytes object to string.
    To call the charm.toolbox.pairinggroup.serialize method, we either instantiate a PairingGroup object with the same
    original pairing curve parameter (such as 'SS512') that was utilized to create the pairing.Element object, and then call the method, or, since
    we need no additional information to call serialize method, we can call the method directly (statically?) without
    instantiating an object. If we want to instantiate an object, we do need the PairingGroup parameter utilized
    to create the pairing.Element object, and thus this parameter must be passed to this KeyEncoder class as argument.
    
    By trial and error and some documentation, we find out that additional arguments can be passed to JSON dumps through
    **kwargs. These extra arguments can only be passed to a subclass of JSONEncoder, however, and not to the superclass
    JSONEncoder, which does not accept the additional arguments. The encoder subclass must override the default method.
    Thus we must use the cls kwarg to specify a subclassed JSONEncoder.
    IMPORTANT! The additional **kwargs arguments are then passed to the *constructor* (__init__) of the encoder
    subclass, and not to the default method. If there is no __init__ method in the subclass, then the superclass __init__
    will be called instead, generating errors (since JSONEncoder does not accept **kwargs). The original implementation
    of dumps in Python's JSON does not catch this problem: if cls is not specified, then JSONEncoder is assumed, and
    **kwargs is passed to it, generating the exception if there is in fact a **kwargs.
    
    In the __init__ constructor method, accept **kwargs, set some instance variable to the appropriate contents of
    arguments (such as capturing the PairingGroup pairing curve param), then remove these parameters from **kwargs dictionary (using
    pop, for instance), and then call JSONEncoder superclass with the remaining **kwargs arguments.
    
    The deserialize method, which will be utilized in another class (not in this class), will basically follow the same
    strategy. However, charm.toolbox.pairinggroup.deserialize does require a Pairing object instantiated with the
    same pairing curve parameter utilized to create the original pairing.Element in order to properly deserialize. If a different
    Pairing object is utilized (with a different parameter), the deserialization will likely produce different values.
    Thus, this parameter, not originally contained in the dictionaries wherein the keys are stored, must be passed as
    argument to a custom, subclassed JSONDecoder. We could perform the decoding in two ways: (a) include the parameter
    in the serialized JSON dictionary, such that a JSON deserialization function could capture it per respective key
    and then instantiate the Pairing object and call charm.toolbox.pairinggroup.deserialize; or (b) pass the PairingGroup
    parameter as extra **kwargs to the subclass from JSONDecoder, and the parameter would then be captured by the
    subclass constructor.
    
    One basic difference in these two strategies is that, in (a), the pairing curve parameter is contained within the JSON dictionary,
    and thus the JSON representation is self-contained. However, the group parameter is turned public (the group parameter
    is not necessarily secret, however; these parameters are exchanged in the open between server and client). In (b),
    the group parameter is not contained within the JSON object and thus must be known a priori to properly deserialize.
    
    At this time, I feel (a), the self-contained JSON object with PairingGroup parameter, is more sensible...
    """
    
    def __init__(self, **kwargs):
        """
        Capture here additional arguments for the serializer.
        
        In the __init__ constructor method, accept **kwargs, set some instance variable to the appropriate contents of
        arguments (such as capturing the PairingGroup param), then remove these parameters from **kwargs dictionary (using
        pop, for instance), and then call JSONEncoder superclass with the remaining **kwargs arguments.
        
        Important argument to capture is 'pairingCurve' parameter, utilized to generate the PairingGroup to serialize
        and include that information within JSON object to allow for proper deserialization.
        Note that only one pairing curve is assumed for a complete JSON serialization/dump. Thus, typically a dictionary
        or Python object containing the keys to serialize has all pairing.Element keys generated from the same
        pairing curve. Even though the serialization does not need the pairing curve paramenter at all, this parameter
        will be included into the JSON object, such that the deserialization utilized the parameter to generate a
        pairing curve object to deserialize. The deserialization can, in fact, manipulate multiple different curves,
        but then the Python object would have to indicate the pairing curve per pairing.Element, and that does not
        happen. (We could include it after generation, however...)
        
        Arguments:
        
        **kwargs: additional parameters for the serializer.
        """
        #print("kwargs: \n", kwargs)        
        if 'pairingCurve' in kwargs:
            # Verify whether argument exists, and define instance variable for pairingCurve.
            self.pairingCurve = kwargs['pairingCurve']
            # Create PairingGroup object.
            self.pairingGroup = charm.toolbox.pairinggroup.PairingGroup(self.pairingCurve)
            # Delete the key such that we can call the original JSONEncoder without it.
            kwargs.pop('pairingCurve')
        # Now call superclass constructor with remaining **kwargs.
        super().__init__(**kwargs)
    
    def default(self, pythonObject):
        """
        Serialize undefined JSON objects here. For pairing.Element objects, use the serialize method
        from charm.toolbox.pairinggroup.
        
        Parameters:
        
        pythonObject: The Python object to serialize (basically transform into a dictionary).
        **kwargs: additional parameters. In particular, we want the PairingGroup pairing curve, such as 'SS512'.
        
        Return: object as dictionary.
        """
        if isinstance(pythonObject, bytes):                                
            return {'__class__': 'bytes',
                    '__value__': base64.b64encode(pythonObject).decode()}
        # This below does not work, as I cannot fetch pairing.Element type from pyd to use with isinstance.
        #    if isinstance(python_object, pairing.Element):                                
        #        return {'__class__': 'charm.core.math.pairing.Element',
        #                '__value__': charm.toolbox.pairinggroup.serialize(python_object).decode()}
        # If "Element" object is present to serialize, then create a dictionary for it.
        # __class__ is pairing.Element.
        # __value__ is the (str) serialized pairing.Element, using the serialize method from PairingGroup as string.
        # __pairingCurve__ is the pairing curve parameter utilized to generate the pairing.Element.
        if pythonObject.__class__.__name__ == 'Element':
            return {'__class__': 'pairing.Element',
                    '__value__': self.pairingGroup.serialize(pythonObject).decode(),
                    '__pairingCurve__': self.pairingCurve} # Save the group parameter for this key within the JSON object.
                    # '__value__': charm.toolbox.pairinggroup.serialize(python_object).decode()}
        
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, pythonObject)
        #raise TypeError(repr(python_object) + ' is not JSON serializable')
        



def serialize_to_json(python_object, **kwargs):
    """
    Serialize undefined JSON types.

    Or better, convert undefined JSON types to a list such that they can be serialized.
    """
                                             
    if isinstance(python_object, bytes):                                
        return {'__class__': 'bytes',
                '__value__': base64.b64encode(python_object).decode()}
    # This below does not work, as I cannot fetch pairing.Element type from pyd to use with isinstance.
#    if isinstance(python_object, pairing.Element):                                
#        return {'__class__': 'charm.core.math.pairing.Element',
#                '__value__': charm.toolbox.pairinggroup.serialize(python_object).decode()}
    if python_object.__class__.__name__ == 'Element':
        return {'__class__': 'pairing.Element',
                '__value__': charm.toolbox.pairinggroup.serialize(python_object).decode()}
    raise TypeError(repr(python_object) + ' is not JSON serializable')
    
    
#==============================================================================
# def __encode_decode(self,data,func):
#         data['IV'] = func(data['IV'])
#         data['CipherText'] = func(data['CipherText'])
#         return data
# 
# #This code should be factored out into  another class
# #Because json is only defined over strings, we need to base64 encode the encrypted data
# # and convert the base 64 byte array into a utf8 string
# def _encode(self,data):
#     return self.__encode_decode(data,lambda x:b64encode(x).decode('utf-8'))
# 
# def _decode(self,data):
#     return self.__encode_decode(data,lambda x:b64decode(bytes(x,'utf-8')))
# 
# def encrypt(self, message):
#     #This should be removed when all crypto functions deal with bytes"
#     if type(message) != bytes :
#         message = bytes(message,"utf-8")
#     ct = self._encrypt(message)
#     #JSON strings cannot have binary data in them, so we must base64 encode  cipher
#     cte = json.dumps(self._encode(ct))
#     return cte
#==============================================================================
