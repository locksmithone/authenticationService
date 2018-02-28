# -*- coding: utf-8 -*-
"""
Created on Tue Jul 28 15:27:04 2015

@author: locksmith
"""

"""
Scripts to create the locationservice.db sqlite3 database.
"""

import sqlite3
import time
import locationserviceutility
import constants

# Create tables.
def createTables():
    """
    This is the complete SQL script to create and populate the database.
    """    
    
    con.executescript("""
        --
        -- File generated with SQLiteStudio v3.0.7 on Thu Nov 10 10:33:09 2016
        --
        -- Text encoding used: windows-1252
        --
        PRAGMA foreign_keys = off;
        BEGIN TRANSACTION;
        
        -- Table: entity
        DROP TABLE IF EXISTS entity;
        
        CREATE TABLE entity (
            primaryKey    INTEGER PRIMARY KEY AUTOINCREMENT
                                  NOT NULL,
            entityID      TEXT    NOT NULL
                                  UNIQUE,
            name          TEXT,
            entityTypeFk  INTEGER REFERENCES entityType (primaryKey) 
                                  NOT NULL,
            creationEpoch REAL
        );
        
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (1, 'locksmithone@hotmail.com', 'Marcos Portnoi', 2, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (2, 'zoolander@gmail.com', 'Zoolander Master', 2, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (3, 'douggiehowser@princeton.edu', 'Douggie Howser', 2, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (4, 'dbbanner@gmail.com', 'Bruce Banner', 2, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (5, 'mrrobot@fsociety.org', 'Edward Alderson', 2, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (6, 'amazon.com', 'Amazon', 1, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (7, 'bestbuy.com', 'Best Buy', 1, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (8, 'udel.edu', 'University of Delaware', 1, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (9, 'newegg.com', 'Newegg', 1, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (10, 'accentfoods.com', 'Accent Food Services', 1, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (11, 'moncalamariexpedia.com', 'Mon Calamari Expedia', 1, 1.46474e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (12, 'gialackbar@live.com', 'Gial Ackbar', 2, 1.46474e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (13, 'location.service', 'Location Service', 3, 1.45022e+09);
        INSERT INTO entity (primaryKey, entityID, name, entityTypeFk, creationEpoch) VALUES (14, 'microsoftstore.com', 'Microsoft Store', 1, 1.45022e+09);
        
        -- Table: entityType
        DROP TABLE IF EXISTS entityType;
        
        CREATE TABLE entityType (
            primaryKey INTEGER PRIMARY KEY AUTOINCREMENT
                               NOT NULL,
            entityType TEXT    UNIQUE
                               NOT NULL
        );
        
        INSERT INTO entityType (
                                   primaryKey,
                                   entityType
                               )
                               VALUES (
                                   1,
                                   'Authority-RP'
                               );
        
        INSERT INTO entityType (
                                   primaryKey,
                                   entityType
                               )
                               VALUES (
                                   2,
                                   'User'
                               );
        
        INSERT INTO entityType (
                                   primaryKey,
                                   entityType
                               )
                               VALUES (
                                   3,
                                   'Location Service'
                               );
        
        
        -- Table: entityAttribute
        DROP TABLE IF EXISTS entityAttribute;
        
        CREATE TABLE entityAttribute (
            primaryKey       INTEGER PRIMARY KEY AUTOINCREMENT
                                     NOT NULL,
            entityFk         INTEGER NOT NULL
                                     REFERENCES entity (primaryKey),
            attributeFk      INTEGER REFERENCES attribute (primaryKey) 
                                     NOT NULL,
            creationEpoch    REAL    NOT NULL,
            expirationEpoch  REAL    NOT NULL,
            lastUpdatedEpoch REAL
        );
        
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (1, 11, 18, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (2, 11, 19, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (3, 11, 20, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (4, 11, 21, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (5, 11, 22, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (6, 11, 23, 1.46474e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (7, 12, 18, 1.46474e+09, 1.49627e+09, 1.46474e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (8, 12, 23, 1.46474e+09, 1.49627e+09, 1.46474e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (9, 13, 1, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (10, 13, 2, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (11, 13, 3, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (12, 13, 4, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (13, 13, 5, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (14, 13, 6, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (15, 13, 7, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (16, 13, 8, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (17, 7, 9, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (18, 7, 10, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (19, 7, 11, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (20, 7, 12, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (21, 7, 13, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (22, 6, 14, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (23, 6, 15, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (24, 6, 16, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (25, 6, 17, 1.47326e+09, 1.51033e+09, 1.4788e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (26, 3, 3, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (27, 3, 5, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (28, 3, 8, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (29, 3, 15, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (30, 3, 17, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (31, 3, 9, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (32, 3, 11, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        INSERT INTO entityAttribute (primaryKey, entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) VALUES (33, 3, 10, 1.4756e+09, 1.50722e+09, 1.47568e+09);
        
        -- Table: entityKey
        DROP TABLE IF EXISTS entityKey;
        
        CREATE TABLE entityKey (
            primaryKey      INTEGER PRIMARY KEY AUTOINCREMENT,
            entityFk        INTEGER NOT NULL
                                    REFERENCES entity (primaryKey),
            [key]           BLOB    NOT NULL,
            salt            BLOB,
            keyTypeFk       INTEGER REFERENCES keyType (primaryKey) 
                                    NOT NULL,
            algorithm       TEXT,
            creationEpoch   REAL    NOT NULL,
            expirationEpoch REAL    NOT NULL,
            lastUsedEpoch   REAL
        );
        
        
        -- Table: attribute
        DROP TABLE IF EXISTS attribute;
        
        CREATE TABLE attribute (
            primaryKey INTEGER PRIMARY KEY AUTOINCREMENT
                               NOT NULL,
            attribute  TEXT    UNIQUE
                               NOT NULL
        );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  1,
                                  'global.locathe'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  2,
                                  'global.payment.mastercard'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  3,
                                  'global.payment.visa'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  4,
                                  'global.payment.paypal'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  5,
                                  'global.payment.androidpay'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  6,
                                  'global.store.bestbuy.com'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  7,
                                  'global.store.microsoftstore.com'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  8,
                                  'global.store.amazon.com'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  9,
                                  'bestbuy.com.vip.platinum'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  10,
                                  'bestbuy.com.vip.gold'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  11,
                                  'bestbuy.com.spendinglimit.level1'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  12,
                                  'bestbuy.com.spendinglimit.level2'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  13,
                                  'bestbuy.com.spendinglimit.level3'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  14,
                                  'amazon.com.spendinglimit.level1'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  15,
                                  'amazon.com.spendinglimit.level2'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  16,
                                  'amazon.com.spendinglimit.level3'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  17,
                                  'amazon.com.vip.prime'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  18,
                                  'moncalamariexpedia.com.vip.platinum'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  19,
                                  'moncalamariexpedia.com.vip.prime'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  20,
                                  'moncalamariexpedia.com.vip.gold'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  21,
                                  'moncalamariexpedia.com.spendinglimit.level1'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  22,
                                  'moncalamariexpedia.com.spendinglimit.level2'
                              );
        
        INSERT INTO attribute (
                                  primaryKey,
                                  attribute
                              )
                              VALUES (
                                  23,
                                  'moncalamariexpedia.com.spendinglimit.level3'
                              );
        
        
        -- Table: keyType
        DROP TABLE IF EXISTS keyType;
        
        CREATE TABLE keyType (
            primaryKey INTEGER PRIMARY KEY AUTOINCREMENT
                               NOT NULL,
            keyType    TEXT    UNIQUE
                               NOT NULL
        );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                1,
                                'Password Hash (KDF)'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                2,
                                'Shared Key'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                3,
                                'ABE Authority Secret Key'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                4,
                                'PKI Secret Key'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                5,
                                'TOTP Seed'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                6,
                                'ABE Authority Public Key'
                            );
        
        INSERT INTO keyType (
                                primaryKey,
                                keyType
                            )
                            VALUES (
                                7,
                                'ABE User Secret Key'
                            );
        
        
        COMMIT TRANSACTION;
PRAGMA foreign_keys = on;

        """)
#    # Create user-password table.
#    con.execute("create table userpassword(userID text, passwordHash text, salt text, algorithm text, expired, lastTimeLogged text)")
#    
#    # Create user table.
#    con.execute("create table user(userID text primary key, name text)")
#    
#    # Create attributes table.
#    con.execute("create table attribute(attribute text unique)")
#    
#    # Create user-attribute table.
#    con.execute("create table userattribute(userID text, attribute text)")
#    
#    # Create user-lastPasswordHash table.
#    con.execute("create table userLastPasswordHash(userID text, passwordHash text, lastTimeUsed text)")


def populateAndTest():
    # Populate some rows.
    attributes = [("global.locathe",), 
                  ("global.payment.mastercard",),
                  ("global.payment.visa",),
                  ("global.payment.paypal",),
                  ("global.payment.androidpay",),
                  ("global.store.bestbuy.com",),
                  ("global.store.microsoftstore.com",),
                  ("global.store.amazon.com",),
                  ("bestbuy.com.vip.platinum",),
                  ("bestbuy.com.vip.gold",),
                  ("bestbuy.com.spendinglimit.level1",),
                  ("bestbuy.com.spendinglimit.level2",),
                  ("bestbuy.com.spendinglimit.level3",),
                  ("amazon.com.spendinglimit.level1",),
                  ("amazon.com.spendinglimit.level2",),
                  ("amazon.com.spendinglimit.level3",),
                  ("amazon.com.vip.prime",)]
                  
    con.executemany("insert into attribute(attribute) values (?)", attributes)
    # Print contents.
    for row in con.execute("select attribute from attribute"):
        print(row)
        if row[0] == "global.payment.visa":
            print("Found visa!")
            
    result = con.execute("select * from attribute where attribute=?", ("global.payment.visa",)).fetchone()[0]
    print(result)
    result = con.execute("select * from attribute where attribute=?", ("global.payment.visa",)).fetchall()
    print(result)
    result = con.execute("select * from attribute where attribute=?", ("no card",)).fetchall()
    print(result)
    
    # Create a few users.
    users = [('locksmithone@hotmail.com', 'Marcos Portnoi', time.time()),
             ('zoolander@gmail.com', 'Zoolander Master', time.time()),
             ('douggiehowser@princeton.edu', 'Douggie Howser', time.time()),
             ('dbbanner@gmail.com', 'Bruce Banner', time.time()),
             ('mrrobot@fsociety.org', 'Mr. Robot', time.time())]
             
    con.executemany("insert into user(entityID, name, creationEpoch) values (?,?,?)", users)
    # Print contents.
    for row in con.execute("select * from user"):
        print(row)
        
    # Insert values into keytype
    keytypedata = [('Password Hash',),
                   ('Shared Key',),
                   ('ABE Secret Key',),
                   ('PKI Secret Key',),
                   ('TOTP Seed',)]
    con.executemany("insert into keyType(keyType) values (?)", keytypedata)
    
def assignAttributesToEntity(database=None):
    """
    This function helps assign attributes that belong to an authority to that authority in the table entityAttribute.
    """
    
    entitySearchStrings = ["global%", "bestbuy.com%", "amazon.com%", "moncalamariexpedia.com%"]
    expirationEpoch = time.time() + constants.DEFAULT_ATTRIBUTE_EXPIRATION_SECONDS
    for entityIDsearch in entitySearchStrings:
        attributes = locationserviceutility.getAllLikeAttributes(entityIDsearch, database=database)
        for attribute in attributes:
            if entityIDsearch == "global%":
                entityIDsearch = constants.ENTITY_ID_LOCATION_SERVICE + "%"
            if locationserviceutility.registerEntityAttribute(entityIDsearch[:-1], attribute, expirationEpoch=expirationEpoch, database = database):
                print("Attribute {} registered to entityID {}.".format(attribute, entityIDsearch[:-1]))
            else:
                print("Attribute {} already registered to entityID {}".format(attribute, entityIDsearch[:-1]))
        
    
    
# Create database.
DATABASE = "locationservicetest.db"
con = sqlite3.connect(DATABASE)

with con:

    createTables()
    #populateAndTest()
    assignAttributesToEntity(database=DATABASE)
