// @flow
// A database adapter that works with data exported from the hosted
// Parse database.

// @flow-disable-next
import { Parse } from 'parse/node';
// @flow-disable-next
import _ from 'lodash';
// @flow-disable-next
import intersect from 'intersect';
// @flow-disable-next
import deepcopy from 'deepcopy';
import logger from '../logger';
import * as SchemaController from './SchemaController';
import { StorageAdapter } from '../Adapters/Storage/StorageAdapter';
import type {
  QueryOptions,
  FullQueryOptions,
} from '../Adapters/Storage/StorageAdapter';

//CD start
const axios = require('axios');
const https = require('https');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function trimObjectKeys(object) {
  return _.fromPairs(
    Object.entries(object).map(entry => {
      return [entry[0].toString().replace(' ', '_'), entry[1]];
    })
  );
}

/* eslint-disable no-unused-vars */
function queryString(delim, fragment, object) {
  var t = _.template(fragment);
  var r = Object.entries(object).map(qu => {
    return t({
      k: qu[0],
      v: qu[1],
    });
  });
  return r.reduce(function(accu, value, i) {
    if (i === 0) {
      return value;
    } else {
      return accu + ' ' + delim + ' ' + value;
    }
  });
}
/* eslint-enable no-unused-vars */
/*
function listString(delim, fragment, array) {
  var r;
  if (fragment) {
    var t = _.template(fragment);
    r = array.map(qu => {
      return t({
        v: qu,
      });
    });
  }
  r = array;
  return r.reduce(function(accu, value, i) {
    if (i === 0) {
      return value;
    } else {
      return accu + delim + ' ' + value;
    }
  });
}
*/
var ConnectorExecute = (path, method, auth, data) => {
  return new Promise((resolve, reject) => {
    axios({
      url: path,
      method: method,
      data: data,
      headers: {
        'Content-Type': 'application/json',
      },
      auth: {
        username: auth.user.attributes.connectorUserName,
        password: auth.user.attributes.connectorUserPassword,
      },
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    })
      .then(response => {
        if (response.status === 200) {
          /*var contactdetails = {
            'name': response.data['First Name'] + ' ' + response.data['Last Name'],
            'emailid': response.data['Email Address'],
            'phonenumber': responsgge.data['Work Phone #']
          }*/
          return resolve(response);
        }
      })
      .catch(err => {
        //console.log(err);
        return reject(
          new Parse.Error(Parse.Error.COMMAND_UNAVAILABLE, err.message)
        );
      });
  });
};
//CD end

function addWriteACL(query, acl) {
  const newQuery = _.cloneDeep(query);
  //Can't be any existing '_wperm' query, we don't allow client queries on that, no need to $and
  newQuery._wperm = { $in: [null, ...acl] };
  return newQuery;
}

function addReadACL(query, acl) {
  const newQuery = _.cloneDeep(query);
  //Can't be any existing '_rperm' query, we don't allow client queries on that, no need to $and
  newQuery._rperm = { $in: [null, '*', ...acl] };
  return newQuery;
}

// Transforms a REST API formatted ACL object to our two-field mongo format.
const transformObjectACL = ({ ACL, ...result }) => {
  if (!ACL) {
    return result;
  }

  result._wperm = [];
  result._rperm = [];

  for (const entry in ACL) {
    if (ACL[entry].read) {
      result._rperm.push(entry);
    }
    if (ACL[entry].write) {
      result._wperm.push(entry);
    }
  }
  return result;
};

const specialQuerykeys = [
  '$and',
  '$or',
  '$nor',
  '_rperm',
  '_wperm',
  '_perishable_token',
  '_email_verify_token',
  '_email_verify_token_expires_at',
  '_account_lockout_expires_at',
  '_failed_login_count',
];

const isSpecialQueryKey = key => {
  return specialQuerykeys.indexOf(key) >= 0;
};

const validateQuery = (query: any): void => {
  if (query.ACL) {
    throw new Parse.Error(Parse.Error.INVALID_QUERY, 'Cannot query on ACL.');
  }

  if (query.$or) {
    if (query.$or instanceof Array) {
      query.$or.forEach(validateQuery);

      /* In MongoDB, $or queries which are not alone at the top level of the
       * query can not make efficient use of indexes due to a long standing
       * bug known as SERVER-13732.
       *
       * This block restructures queries in which $or is not the sole top
       * level element by moving all other top-level predicates inside every
       * subdocument of the $or predicate, allowing MongoDB's query planner
       * to make full use of the most relevant indexes.
       *
       * EG:      {$or: [{a: 1}, {a: 2}], b: 2}
       * Becomes: {$or: [{a: 1, b: 2}, {a: 2, b: 2}]}
       *
       * The only exceptions are $near and $nearSphere operators, which are
       * constrained to only 1 operator per query. As a result, these ops
       * remain at the top level
       *
       * https://jira.mongodb.org/browse/SERVER-13732
       * https://github.com/parse-community/parse-server/issues/3767
       */
      Object.keys(query).forEach(key => {
        const noCollisions = !query.$or.some(subq => subq.hasOwnProperty(key));
        let hasNears = false;
        if (query[key] != null && typeof query[key] == 'object') {
          hasNears = '$near' in query[key] || '$nearSphere' in query[key];
        }
        if (key != '$or' && noCollisions && !hasNears) {
          query.$or.forEach(subquery => {
            subquery[key] = query[key];
          });
          delete query[key];
        }
      });
      query.$or.forEach(validateQuery);
    } else {
      throw new Parse.Error(
        Parse.Error.INVALID_QUERY,
        'Bad $or format - use an array value.'
      );
    }
  }

  if (query.$and) {
    if (query.$and instanceof Array) {
      query.$and.forEach(validateQuery);
    } else {
      throw new Parse.Error(
        Parse.Error.INVALID_QUERY,
        'Bad $and format - use an array value.'
      );
    }
  }

  if (query.$nor) {
    if (query.$nor instanceof Array && query.$nor.length > 0) {
      query.$nor.forEach(validateQuery);
    } else {
      throw new Parse.Error(
        Parse.Error.INVALID_QUERY,
        'Bad $nor format - use an array of at least 1 value.'
      );
    }
  }

  Object.keys(query).forEach(key => {
    if (query && query[key] && query[key].$regex) {
      if (typeof query[key].$options === 'string') {
        if (!query[key].$options.match(/^[imxs]+$/)) {
          throw new Parse.Error(
            Parse.Error.INVALID_QUERY,
            `Bad $options value for query: ${query[key].$options}`
          );
        }
      }
    }
    if (!isSpecialQueryKey(key) && !key.match(/^[a-zA-Z][a-zA-Z0-9_\.]*$/)) {
      throw new Parse.Error(
        Parse.Error.INVALID_KEY_NAME,
        `Invalid key name: ${key}`
      );
    }
  });
};

// Filters out any data that shouldn't be on this REST-formatted object.
const filterSensitiveData = (
  isMaster,
  aclGroup,
  className,
  protectedFields,
  object
) => {
  protectedFields && protectedFields.forEach(k => delete object[k]);

  if (className !== '_User') {
    return object;
  }

  object.password = object._hashed_password;
  delete object._hashed_password;

  delete object.sessionToken;

  if (isMaster) {
    return object;
  }
  delete object._email_verify_token;
  delete object._perishable_token;
  delete object._perishable_token_expires_at;
  delete object._tombstone;
  delete object._email_verify_token_expires_at;
  delete object._failed_login_count;
  delete object._account_lockout_expires_at;
  delete object._password_changed_at;
  delete object._password_history;

  if (aclGroup.indexOf(object.objectId) > -1) {
    return object;
  }
  delete object.authData;
  return object;
};

import type { LoadSchemaOptions } from './types';

// Runs an update on the database.
// Returns a promise for an object with the new values for field
// modifications that don't know their results ahead of time, like
// 'increment'.
// Options:
//   acl:  a list of strings. If the object to be updated has an ACL,
//         one of the provided strings must provide the caller with
//         write permissions.
const specialKeysForUpdate = [
  '_hashed_password',
  '_perishable_token',
  '_email_verify_token',
  '_email_verify_token_expires_at',
  '_account_lockout_expires_at',
  '_failed_login_count',
  '_perishable_token_expires_at',
  '_password_changed_at',
  '_password_history',
];

const isSpecialUpdateKey = key => {
  return specialKeysForUpdate.indexOf(key) >= 0;
};

function expandResultOnKeyPath(object, key, value) {
  if (key.indexOf('.') < 0) {
    object[key] = value[key];
    return object;
  }
  const path = key.split('.');
  const firstKey = path[0];
  const nextPath = path.slice(1).join('.');
  object[firstKey] = expandResultOnKeyPath(
    object[firstKey] || {},
    nextPath,
    value[firstKey]
  );
  delete object[key];
  return object;
}

function sanitizeDatabaseResult(originalObject, result): Promise<any> {
  const response = {};
  if (!result) {
    return Promise.resolve(response);
  }
  Object.keys(originalObject).forEach(key => {
    const keyUpdate = originalObject[key];
    // determine if that was an op
    if (
      keyUpdate &&
      typeof keyUpdate === 'object' &&
      keyUpdate.__op &&
      ['Add', 'AddUnique', 'Remove', 'Increment'].indexOf(keyUpdate.__op) > -1
    ) {
      // only valid ops that produce an actionable result
      // the op may have happend on a keypath
      expandResultOnKeyPath(response, key, result);
    }
  });
  return Promise.resolve(response);
}

function joinTableName(className, key) {
  return `_Join:${key}:${className}`;
}

const flattenUpdateOperatorsForCreate = object => {
  for (const key in object) {
    if (object[key] && object[key].__op) {
      switch (object[key].__op) {
        case 'Increment':
          if (typeof object[key].amount !== 'number') {
            throw new Parse.Error(
              Parse.Error.INVALID_JSON,
              'objects to add must be an array'
            );
          }
          object[key] = object[key].amount;
          break;
        case 'Add':
          if (!(object[key].objects instanceof Array)) {
            throw new Parse.Error(
              Parse.Error.INVALID_JSON,
              'objects to add must be an array'
            );
          }
          object[key] = object[key].objects;
          break;
        case 'AddUnique':
          if (!(object[key].objects instanceof Array)) {
            throw new Parse.Error(
              Parse.Error.INVALID_JSON,
              'objects to add must be an array'
            );
          }
          object[key] = object[key].objects;
          break;
        case 'Remove':
          if (!(object[key].objects instanceof Array)) {
            throw new Parse.Error(
              Parse.Error.INVALID_JSON,
              'objects to add must be an array'
            );
          }
          object[key] = [];
          break;
        case 'Delete':
          delete object[key];
          break;
        default:
          throw new Parse.Error(
            Parse.Error.COMMAND_UNAVAILABLE,
            `The ${object[key].__op} operator is not supported yet.`
          );
      }
    }
  }
};

const transformAuthData = (className, object, schema) => {
  if (object.authData && className === '_User') {
    Object.keys(object.authData).forEach(provider => {
      const providerData = object.authData[provider];
      const fieldName = `_auth_data_${provider}`;
      if (providerData == null) {
        object[fieldName] = {
          __op: 'Delete',
        };
      } else {
        object[fieldName] = providerData;
        schema.fields[fieldName] = { type: 'Object' };
      }
    });
    delete object.authData;
  }
};
// Transforms a Database format ACL to a REST API format ACL
const untransformObjectACL = ({ _rperm, _wperm, ...output }) => {
  if (_rperm || _wperm) {
    output.ACL = {};

    (_rperm || []).forEach(entry => {
      if (!output.ACL[entry]) {
        output.ACL[entry] = { read: true };
      } else {
        output.ACL[entry]['read'] = true;
      }
    });

    (_wperm || []).forEach(entry => {
      if (!output.ACL[entry]) {
        output.ACL[entry] = { write: true };
      } else {
        output.ACL[entry]['write'] = true;
      }
    });
  }
  return output;
};

/**
 * When querying, the fieldName may be compound, extract the root fieldName
 *     `temperature.celsius` becomes `temperature`
 * @param {string} fieldName that may be a compound field name
 * @returns {string} the root name of the field
 */
const getRootFieldName = (fieldName: string): string => {
  return fieldName.split('.')[0];
};

const relationSchema = {
  fields: { relatedId: { type: 'String' }, owningId: { type: 'String' } },
};

class DatabaseController {
  adapter: StorageAdapter;
  schemaCache: any;
  schemaPromise: ?Promise<SchemaController.SchemaController>;

  constructor(adapter: StorageAdapter, schemaCache: any) {
    this.adapter = adapter;
    this.schemaCache = schemaCache;
    // We don't want a mutable this.schema, because then you could have
    // one request that uses different schemas for different parts of
    // it. Instead, use loadSchema to get a schema.
    this.schemaPromise = null;
  }

  collectionExists(className: string): Promise<boolean> {
    return this.adapter.classExists(className);
  }

  purgeCollection(className: string): Promise<void> {
    return this.loadSchema()
      .then(schemaController => schemaController.getOneSchema(className))
      .then(schema => this.adapter.deleteObjectsByQuery(className, schema, {}));
  }

  validateClassName(className: string): Promise<void> {
    if (!SchemaController.classNameIsValid(className)) {
      return Promise.reject(
        new Parse.Error(
          Parse.Error.INVALID_CLASS_NAME,
          'invalid className: ' + className
        )
      );
    }
    return Promise.resolve();
  }

  // Returns a promise for a schemaController.
  loadSchema(
    options: LoadSchemaOptions = { clearCache: false }
  ): Promise<SchemaController.SchemaController> {
    if (this.schemaPromise != null) {
      return this.schemaPromise;
    }
    this.schemaPromise = SchemaController.load(
      this.adapter,
      this.schemaCache,
      options
    );
    this.schemaPromise.then(
      () => delete this.schemaPromise,
      () => delete this.schemaPromise
    );
    return this.loadSchema(options);
  }

  // Returns a promise for the classname that is related to the given
  // classname through the key.
  // TODO: make this not in the DatabaseController interface
  redirectClassNameForKey(className: string, key: string): Promise<?string> {
    return this.loadSchema().then(schema => {
      var t = schema.getExpectedType(className, key);
      if (t != null && typeof t !== 'string' && t.type === 'Relation') {
        return t.targetClass;
      }
      return className;
    });
  }

  // Uses the schema to validate the object (REST API format).
  // Returns a promise that resolves to the new schema.
  // This does not update this.schema, because in a situation like a
  // batch request, that could confuse other users of the schema.
  validateObject(
    className: string,
    object: any,
    query: any,
    { acl }: QueryOptions
  ): Promise<boolean> {
    let schema;
    const isMaster = acl === undefined;
    var aclGroup: string[] = acl || [];
    return this.loadSchema()
      .then(s => {
        schema = s;
        if (isMaster) {
          return Promise.resolve();
        }
        return this.canAddField(schema, className, object, aclGroup);
      })
      .then(() => {
        return schema.validateObject(className, object, query);
      });
  }

  update(
    className: string,
    query: any,
    update: any,
    { acl, many, upsert }: FullQueryOptions = {},
    skipSanitization: boolean = false,
    auth
  ): Promise<any> {
    const originalQuery = query;
    const originalUpdate = update;
    // Make a copy of the object, so we don't mutate the incoming data.
    update = deepcopy(update);
    var relationUpdates = [];
    var isMaster = acl === undefined;
    var aclGroup = acl || [];
    return this.loadSchema().then(schemaController => {
      return (isMaster
        ? Promise.resolve()
        : schemaController.validatePermission(className, aclGroup, 'update')
      ).then(() => {
        relationUpdates = this.collectRelationUpdates(
          className,
          originalQuery.objectId,
          update
        );
        if (!isMaster) {
          query = this.addPointerPermissions(
            schemaController,
            className,
            'update',
            query,
            aclGroup
          );
        }
        if (!query) {
          return Promise.resolve();
        }
        if (acl) {
          query = addWriteACL(query, acl);
        }
        validateQuery(query);
        return schemaController
          .getOneSchema(className, true)
          .catch(error => {
            // If the schema doesn't exist, pretend it exists with no fields. This behavior
            // will likely need revisiting.
            if (error === undefined) {
              return { fields: {} };
            }
            throw error;
          })
          .then(schema => {
            Object.keys(update).forEach(fieldName => {
              if (fieldName.match(/^authData\.([a-zA-Z0-9_]+)\.id$/)) {
                throw new Parse.Error(
                  Parse.Error.INVALID_KEY_NAME,
                  `Invalid field name for update: ${fieldName}`
                );
              }
              const rootFieldName = getRootFieldName(fieldName);
              if (
                !SchemaController.fieldNameIsValid(rootFieldName) &&
                !isSpecialUpdateKey(rootFieldName)
              ) {
                throw new Parse.Error(
                  Parse.Error.INVALID_KEY_NAME,
                  `Invalid field name for update: ${fieldName}`
                );
              }
            });
            for (const updateOperation in update) {
              if (
                update[updateOperation] &&
                typeof update[updateOperation] === 'object' &&
                Object.keys(update[updateOperation]).some(
                  innerKey => innerKey.includes('$') || innerKey.includes('.')
                )
              ) {
                throw new Parse.Error(
                  Parse.Error.INVALID_NESTED_KEY,
                  "Nested keys should not contain the '$' or '.' characters"
                );
              }
            }
            update = transformObjectACL(update);
            transformAuthData(className, update, schema);
            if (many) {
              return this.adapter.updateObjectsByQuery(
                className,
                schema,
                query,
                update
              );
            } else if (upsert) {
              return this.adapter.upsertOneObject(
                className,
                schema,
                query,
                update
              );
            } else {
              return this.adapter
                .findOneAndUpdate(className, schema, query, update)
                .then(updateResponse => {
                  if (updateResponse && schema.backendClass) {
                    var bindObj = {};
                    var backendBasedFieldsQuery = this.stripSpecialQueryKeys(
                      query
                    );
                    return this.convertParseQueryToConnectorQuery(
                      className,
                      schema,
                      backendBasedFieldsQuery
                    ).then(connectorQuery => {
                      Object.assign(bindObj, connectorQuery);
                      return this.convertParseDataToConnectorData(
                        schema,
                        update,
                        updateResponse
                      ).then(payLoad => {
                        Object.assign(bindObj, payLoad);
                        var connectorURI;
                        var compileConnectorURI = _.template(
                          schema.backendClass.update
                        );
                        var trimmedBindObj = trimObjectKeys(bindObj); // Just to avoid the pesky whitespaces causing _.template to bomb
                        try {
                          connectorURI = compileConnectorURI(trimmedBindObj);
                        } catch (err) {
                          throw new Parse.Error(
                            Parse.Error.INTERNAL_SERVER_ERROR,
                            err.message
                          );
                        }

                        payLoad.Id = connectorQuery.Id; // this is due to a bug in Siebel, will remove this once the requirement to supply a bogus Id is fixed

                        return ConnectorExecute(
                          connectorURI,
                          'put',
                          auth,
                          payLoad
                        );
                      });
                    });
                  } else {
                    return updateResponse;
                  }
                });
            }
          })
          .then((result: any) => {
            if (!result) {
              throw new Parse.Error(
                Parse.Error.OBJECT_NOT_FOUND,
                'Object not found.'
              );
            }
            return this.handleRelationUpdates(
              className,
              originalQuery.objectId,
              update,
              relationUpdates
            ).then(() => {
              return result;
            });
          })
          .then(result => {
            if (skipSanitization) {
              return Promise.resolve(result);
            }
            return sanitizeDatabaseResult(originalUpdate, result);
          });
      });
    });
  }

  // Collect all relation-updating operations from a REST-format update.
  // Returns a list of all relation updates to perform
  // This mutates update.
  collectRelationUpdates(className: string, objectId: ?string, update: any) {
    var ops = [];
    var deleteMe = [];
    objectId = update.objectId || objectId;

    var process = (op, key) => {
      if (!op) {
        return;
      }
      if (op.__op == 'AddRelation') {
        ops.push({ key, op });
        deleteMe.push(key);
      }

      if (op.__op == 'RemoveRelation') {
        ops.push({ key, op });
        deleteMe.push(key);
      }

      if (op.__op == 'Batch') {
        for (var x of op.ops) {
          process(x, key);
        }
      }
    };

    for (const key in update) {
      process(update[key], key);
    }
    for (const key of deleteMe) {
      delete update[key];
    }
    return ops;
  }

  // Processes relation-updating operations from a REST-format update.
  // Returns a promise that resolves when all updates have been performed
  handleRelationUpdates(
    className: string,
    objectId: string,
    update: any,
    ops: any
  ) {
    var pending = [];
    objectId = update.objectId || objectId;
    ops.forEach(({ key, op }) => {
      if (!op) {
        return;
      }
      if (op.__op == 'AddRelation') {
        for (const object of op.objects) {
          pending.push(
            this.addRelation(key, className, objectId, object.objectId)
          );
        }
      }

      if (op.__op == 'RemoveRelation') {
        for (const object of op.objects) {
          pending.push(
            this.removeRelation(key, className, objectId, object.objectId)
          );
        }
      }
    });

    return Promise.all(pending);
  }

  // Adds a relation.
  // Returns a promise that resolves successfully iff the add was successful.
  addRelation(
    key: string,
    fromClassName: string,
    fromId: string,
    toId: string
  ) {
    const doc = {
      relatedId: toId,
      owningId: fromId,
    };
    return this.adapter.upsertOneObject(
      `_Join:${key}:${fromClassName}`,
      relationSchema,
      doc,
      doc
    );
  }

  // Removes a relation.
  // Returns a promise that resolves successfully iff the remove was
  // successful.
  removeRelation(
    key: string,
    fromClassName: string,
    fromId: string,
    toId: string
  ) {
    var doc = {
      relatedId: toId,
      owningId: fromId,
    };
    return this.adapter
      .deleteObjectsByQuery(
        `_Join:${key}:${fromClassName}`,
        relationSchema,
        doc
      )
      .catch(error => {
        // We don't care if they try to delete a non-existent relation.
        if (error.code == Parse.Error.OBJECT_NOT_FOUND) {
          return;
        }
        throw error;
      });
  }

  // Removes objects matches this query from the database.
  // Returns a promise that resolves successfully iff the object was
  // deleted.
  // Options:
  //   acl:  a list of strings. If the object to be updated has an ACL,
  //         one of the provided strings must provide the caller with
  //         write permissions.
  destroy(
    className: string,
    query: any,
    { acl }: QueryOptions = {}
  ): Promise<any> {
    const isMaster = acl === undefined;
    const aclGroup = acl || [];

    return this.loadSchema().then(schemaController => {
      return (isMaster
        ? Promise.resolve()
        : schemaController.validatePermission(className, aclGroup, 'delete')
      ).then(() => {
        if (!isMaster) {
          query = this.addPointerPermissions(
            schemaController,
            className,
            'delete',
            query,
            aclGroup
          );
          if (!query) {
            throw new Parse.Error(
              Parse.Error.OBJECT_NOT_FOUND,
              'Object not found.'
            );
          }
        }
        // delete by query
        if (acl) {
          query = addWriteACL(query, acl);
        }
        validateQuery(query);
        return schemaController
          .getOneSchema(className)
          .catch(error => {
            // If the schema doesn't exist, pretend it exists with no fields. This behavior
            // will likely need revisiting.
            if (error === undefined) {
              return { fields: {} };
            }
            throw error;
          })
          .then(parseFormatSchema =>
            this.adapter.deleteObjectsByQuery(
              className,
              parseFormatSchema,
              query
            )
          )
          .catch(error => {
            // When deleting sessions while changing passwords, don't throw an error if they don't have any sessions.
            if (
              className === '_Session' &&
              error.code === Parse.Error.OBJECT_NOT_FOUND
            ) {
              return Promise.resolve({});
            }
            throw error;
          });
      });
    });
  }

  // Inserts an object into the database.
  // Returns a promise that resolves successfully iff the object saved.
  create(
    className: string,
    object: any,
    { acl }: QueryOptions = {},
    auth
  ): Promise<any> {
    // Make a copy of the object, so we don't mutate the incoming data.
    const originalObject = object;
    object = transformObjectACL(object);

    object.createdAt = { iso: object.createdAt, __type: 'Date' };
    object.updatedAt = { iso: object.updatedAt, __type: 'Date' };

    var isMaster = acl === undefined;
    var aclGroup = acl || [];
    const relationUpdates = this.collectRelationUpdates(
      className,
      null,
      object
    );
    return this.validateClassName(className)
      .then(() => this.loadSchema())
      .then(schemaController => {
        return (isMaster
          ? Promise.resolve()
          : schemaController.validatePermission(className, aclGroup, 'create')
        )
          .then(() => schemaController.enforceClassExists(className))
          .then(() => schemaController.reloadData())
          .then(() => schemaController.getOneSchema(className, true))
          .then(schema => {
            transformAuthData(className, object, schema);
            flattenUpdateOperatorsForCreate(object);
            if (schema.backendClass) {
              return this.convertParseDataToConnectorData(schema, object)
                .then(payLoad => {
                  var connectorURI;
                  var compileConnectorURI = _.template(
                    schema.backendClass.base.uri
                  );
                  var trimmedPayLoad = trimObjectKeys(payLoad); // Just to avoid the pesky whitespaces causing _.template to bomb
                  try {
                    connectorURI = compileConnectorURI(trimmedPayLoad);
                  } catch (err) {
                    throw new Parse.Error(
                      Parse.Error.INTERNAL_SERVER_ERROR,
                      err.message
                    );
                  }

                  var kludgePayLoad = {};
                  Object.assign(kludgePayLoad, payLoad);
                  if (schema.backendClass.base.method === 'PUT') {
                    kludgePayLoad.Id = 'something'; // this is due to a bug in Siebel, will remove this once the requirement to supply a bogus Id is fixed
                  }

                  return ConnectorExecute(
                    connectorURI,
                    schema.backendClass.base.method,
                    auth,
                    kludgePayLoad
                  ).then(response => [payLoad, response]);
                })
                .then(
                  ([
                    connectorQuery,
                    connectorResponse,
                  ]) /*dont change this name!*/ => {
                    if (schema.backendClass.base.fetchAfterCreate === true) {
                      var backendBasedFieldsResponseQuery = this.stripSpecialQueryKeys(
                        connectorQuery
                      );
                      var trimmedQuery = trimObjectKeys(
                        backendBasedFieldsResponseQuery
                      );

                      Object.keys(trimmedQuery).forEach(key => {
                        global[key] = trimmedQuery[key];
                      });
                      var connectorURI;

                      connectorURI = eval(
                        '`' + schema.backendClass.query + '`;'
                      );
                      Object.keys(trimmedQuery).forEach(key => {
                        delete global[key];
                      });
                      //console.log(connectorURI);
                      return ConnectorExecute(connectorURI, 'get', auth);
                    } else {
                      return connectorResponse;
                    }
                  }
                )
                .then(connectorResponse => {
                  if (schema.backendClass.base.fetchAfterCreate === true) {
                    if (connectorResponse.data.items.length != 1) {
                      /* eslint-disable no-console */
                      //Add implementation here for disabling currect expense report till manual insertion of connectorId
                      console.log(
                        'Multiple records returned on fetchAfterCreate - please manually update connectorId'
                      );
                      /* eslint-enable no-console */
                    } else {
                      object.connectorId = connectorResponse.data.items[0].Id;
                    }
                  } else {
                    object.connectorId = connectorResponse.data.items.Id;
                  }
                  return this.adapter
                    .createObject(
                      className,
                      SchemaController.convertSchemaToAdapterSchema(schema),
                      object
                    )
                    .then(result => {
                      return this.handleRelationUpdates(
                        className,
                        object.objectId,
                        object,
                        relationUpdates
                      ).then(() => {
                        return sanitizeDatabaseResult(
                          originalObject,
                          result.ops[0]
                        );
                      });
                    });
                })
                .catch(err => {
                  throw err;
                });
            } else {
              return this.adapter
                .createObject(
                  className,
                  SchemaController.convertSchemaToAdapterSchema(schema),
                  object
                )
                .then(result => {
                  return this.handleRelationUpdates(
                    className,
                    object.objectId,
                    object,
                    relationUpdates
                  ).then(() => {
                    return sanitizeDatabaseResult(
                      originalObject,
                      result.ops[0]
                    );
                  });
                });
            }
          });
        /*.then(result => {
            return this.handleRelationUpdates(
              className,
              object.objectId,
              object,
              relationUpdates
            ).then(() => {
              return sanitizeDatabaseResult(originalObject, result.ops[0]);
            });
          });*/
      });
  }

  canAddField(
    schema: SchemaController.SchemaController,
    className: string,
    object: any,
    aclGroup: string[]
  ): Promise<void> {
    const classSchema = schema.schemaData[className];
    if (!classSchema) {
      return Promise.resolve();
    }
    const fields = Object.keys(object);
    const schemaFields = Object.keys(classSchema.fields);
    const newKeys = fields.filter(field => {
      // Skip fields that are unset
      if (
        object[field] &&
        object[field].__op &&
        object[field].__op === 'Delete'
      ) {
        return false;
      }
      return schemaFields.indexOf(field) < 0;
    });
    if (newKeys.length > 0) {
      return schema.validatePermission(className, aclGroup, 'addField');
    }
    return Promise.resolve();
  }

  // Won't delete collections in the system namespace
  /**
   * Delete all classes and clears the schema cache
   *
   * @param {boolean} fast set to true if it's ok to just delete rows and not indexes
   * @returns {Promise<void>} when the deletions completes
   */
  deleteEverything(fast: boolean = false): Promise<any> {
    this.schemaPromise = null;
    return Promise.all([
      this.adapter.deleteAllClasses(fast),
      this.schemaCache.clear(),
    ]);
  }

  // Returns a promise for a list of related ids given an owning id.
  // className here is the owning className.
  relatedIds(
    className: string,
    key: string,
    owningId: string,
    queryOptions: QueryOptions
  ): Promise<Array<string>> {
    const { skip, limit, sort } = queryOptions;
    const findOptions = {};
    if (sort && sort.createdAt && this.adapter.canSortOnJoinTables) {
      findOptions.sort = { _id: sort.createdAt };
      findOptions.limit = limit;
      findOptions.skip = skip;
      queryOptions.skip = 0;
    }
    return this.adapter
      .find(
        joinTableName(className, key),
        relationSchema,
        { owningId },
        findOptions
      )
      .then(results => results.map(result => result.relatedId));
  }

  // Returns a promise for a list of owning ids given some related ids.
  // className here is the owning className.
  owningIds(
    className: string,
    key: string,
    relatedIds: string[]
  ): Promise<string[]> {
    return this.adapter
      .find(
        joinTableName(className, key),
        relationSchema,
        { relatedId: { $in: relatedIds } },
        {}
      )
      .then(results => results.map(result => result.owningId));
  }

  // Modifies query so that it no longer has $in on relation fields, or
  // equal-to-pointer constraints on relation fields.
  // Returns a promise that resolves when query is mutated
  reduceInRelation(className: string, query: any, schema: any): Promise<any> {
    // Search for an in-relation or equal-to-relation
    // Make it sequential for now, not sure of paralleization side effects
    if (query['$or']) {
      const ors = query['$or'];
      return Promise.all(
        ors.map((aQuery, index) => {
          return this.reduceInRelation(className, aQuery, schema).then(
            aQuery => {
              query['$or'][index] = aQuery;
            }
          );
        })
      ).then(() => {
        return Promise.resolve(query);
      });
    }

    const promises = Object.keys(query).map(key => {
      const t = schema.getExpectedType(className, key);
      if (!t || t.type !== 'Relation') {
        return Promise.resolve(query);
      }
      let queries: ?(any[]) = null;
      if (
        query[key] &&
        (query[key]['$in'] ||
          query[key]['$ne'] ||
          query[key]['$nin'] ||
          query[key].__type == 'Pointer')
      ) {
        // Build the list of queries
        queries = Object.keys(query[key]).map(constraintKey => {
          let relatedIds;
          let isNegation = false;
          if (constraintKey === 'objectId') {
            relatedIds = [query[key].objectId];
          } else if (constraintKey == '$in') {
            relatedIds = query[key]['$in'].map(r => r.objectId);
          } else if (constraintKey == '$nin') {
            isNegation = true;
            relatedIds = query[key]['$nin'].map(r => r.objectId);
          } else if (constraintKey == '$ne') {
            isNegation = true;
            relatedIds = [query[key]['$ne'].objectId];
          } else {
            return;
          }
          return {
            isNegation,
            relatedIds,
          };
        });
      } else {
        queries = [{ isNegation: false, relatedIds: [] }];
      }

      // remove the current queryKey as we don,t need it anymore
      delete query[key];
      // execute each query independently to build the list of
      // $in / $nin
      const promises = queries.map(q => {
        if (!q) {
          return Promise.resolve();
        }
        return this.owningIds(className, key, q.relatedIds).then(ids => {
          if (q.isNegation) {
            this.addNotInObjectIdsIds(ids, query);
          } else {
            this.addInObjectIdsIds(ids, query);
          }
          return Promise.resolve();
        });
      });

      return Promise.all(promises).then(() => {
        return Promise.resolve();
      });
    });

    return Promise.all(promises).then(() => {
      return Promise.resolve(query);
    });
  }

  // Modifies query so that it no longer has $relatedTo
  // Returns a promise that resolves when query is mutated
  reduceRelationKeys(
    className: string,
    query: any,
    queryOptions: any
  ): ?Promise<void> {
    if (query['$or']) {
      return Promise.all(
        query['$or'].map(aQuery => {
          return this.reduceRelationKeys(className, aQuery, queryOptions);
        })
      );
    }

    var relatedTo = query['$relatedTo'];
    if (relatedTo) {
      return this.relatedIds(
        relatedTo.object.className,
        relatedTo.key,
        relatedTo.object.objectId,
        queryOptions
      )
        .then(ids => {
          delete query['$relatedTo'];
          this.addInObjectIdsIds(ids, query);
          return this.reduceRelationKeys(className, query, queryOptions);
        })
        .then(() => {});
    }
  }

  addInObjectIdsIds(ids: ?Array<string> = null, query: any) {
    const idsFromString: ?Array<string> =
      typeof query.objectId === 'string' ? [query.objectId] : null;
    const idsFromEq: ?Array<string> =
      query.objectId && query.objectId['$eq'] ? [query.objectId['$eq']] : null;
    const idsFromIn: ?Array<string> =
      query.objectId && query.objectId['$in'] ? query.objectId['$in'] : null;

    // @flow-disable-next
    const allIds: Array<Array<string>> = [
      idsFromString,
      idsFromEq,
      idsFromIn,
      ids,
    ].filter(list => list !== null);
    const totalLength = allIds.reduce((memo, list) => memo + list.length, 0);

    let idsIntersection = [];
    if (totalLength > 125) {
      idsIntersection = intersect.big(allIds);
    } else {
      idsIntersection = intersect(allIds);
    }

    // Need to make sure we don't clobber existing shorthand $eq constraints on objectId.
    if (!('objectId' in query)) {
      query.objectId = {
        $in: undefined,
      };
    } else if (typeof query.objectId === 'string') {
      query.objectId = {
        $in: undefined,
        $eq: query.objectId,
      };
    }
    query.objectId['$in'] = idsIntersection;

    return query;
  }

  addNotInObjectIdsIds(ids: string[] = [], query: any) {
    const idsFromNin =
      query.objectId && query.objectId['$nin'] ? query.objectId['$nin'] : [];
    let allIds = [...idsFromNin, ...ids].filter(list => list !== null);

    // make a set and spread to remove duplicates
    allIds = [...new Set(allIds)];

    // Need to make sure we don't clobber existing shorthand $eq constraints on objectId.
    if (!('objectId' in query)) {
      query.objectId = {
        $nin: undefined,
      };
    } else if (typeof query.objectId === 'string') {
      query.objectId = {
        $nin: undefined,
        $eq: query.objectId,
      };
    }

    query.objectId['$nin'] = allIds;
    return query;
  }

  // Runs a query on the database.
  // Returns a promise that resolves to a list of items.
  // Options:
  //   skip    number of results to skip.
  //   limit   limit to this number of results.
  //   sort    an object where keys are the fields to sort by.
  //           the value is +1 for ascending, -1 for descending.
  //   count   run a count instead of returning results.
  //   acl     restrict this operation with an ACL for the provided array
  //           of user objectIds and roles. acl: null means no user.
  //           when this field is not present, don't do anything regarding ACLs.
  // TODO: make userIds not needed here. The db adapter shouldn't know
  // anything about users, ideally. Then, improve the format of the ACL
  // arg to work like the others.
  find(
    className: string,
    query: any,
    {
      skip,
      limit,
      acl,
      sort = {},
      count,
      keys,
      op,
      distinct,
      pipeline,
      readPreference,
    }: any = {},
    auth: any = {}
  ): Promise<any> {
    const isMaster = acl === undefined;
    const aclGroup = acl || [];
    op =
      op ||
      (typeof query.objectId == 'string' && Object.keys(query).length === 1
        ? 'get'
        : 'find');
    // Count operation if counting
    op = count === true ? 'count' : op;

    let classExists = true;
    return this.loadSchema().then(schemaController => {
      //Allow volatile classes if querying with Master (for _PushStatus)
      //TODO: Move volatile classes concept into mongo adapter, postgres adapter shouldn't care
      //that api.parse.com breaks when _PushStatus exists in mongo.
      return schemaController
        .getOneSchema(className, isMaster)
        .catch(error => {
          // Behavior for non-existent classes is kinda weird on Parse.com. Probably doesn't matter too much.
          // For now, pretend the class exists but has no objects,
          if (error === undefined) {
            classExists = false;
            return { fields: {} };
          }
          throw error;
        })
        .then(schema => {
          // Parse.com treats queries on _created_at and _updated_at as if they were queries on createdAt and updatedAt,
          // so duplicate that behavior here. If both are specified, the correct behavior to match Parse.com is to
          // use the one that appears first in the sort list.
          if (sort._created_at) {
            sort.createdAt = sort._created_at;
            delete sort._created_at;
          }
          if (sort._updated_at) {
            sort.updatedAt = sort._updated_at;
            delete sort._updated_at;
          }
          const queryOptions = { skip, limit, sort, keys, readPreference };
          Object.keys(sort).forEach(fieldName => {
            if (fieldName.match(/^authData\.([a-zA-Z0-9_]+)\.id$/)) {
              throw new Parse.Error(
                Parse.Error.INVALID_KEY_NAME,
                `Cannot sort by ${fieldName}`
              );
            }
            const rootFieldName = getRootFieldName(fieldName);
            if (!SchemaController.fieldNameIsValid(rootFieldName)) {
              throw new Parse.Error(
                Parse.Error.INVALID_KEY_NAME,
                `Invalid field name: ${fieldName}.`
              );
            }
          });
          return (isMaster
            ? Promise.resolve()
            : schemaController.validatePermission(className, aclGroup, op)
          )
            .then(() => this.reduceRelationKeys(className, query, queryOptions))
            .then(() =>
              this.reduceInRelation(className, query, schemaController)
            )
            .then(() => {
              let protectedFields;
              if (!isMaster) {
                query = this.addPointerPermissions(
                  schemaController,
                  className,
                  op,
                  query,
                  aclGroup
                );
                // ProtectedFields is generated before executing the query so we
                // can optimize the query using Mongo Projection at a later stage.
                protectedFields = this.addProtectedFields(
                  schemaController,
                  className,
                  query,
                  aclGroup,
                  auth
                );
              }
              if (!query) {
                if (op === 'get') {
                  throw new Parse.Error(
                    Parse.Error.OBJECT_NOT_FOUND,
                    'Object not found.'
                  );
                } else {
                  return [];
                }
              }
              if (!isMaster) {
                if (op === 'update' || op === 'delete') {
                  query = addWriteACL(query, aclGroup);
                } else {
                  query = addReadACL(query, aclGroup);
                }
              }
              validateQuery(query);
              if (count) {
                if (!classExists) {
                  return 0;
                } else {
                  return this.adapter.count(
                    className,
                    schema,
                    query,
                    readPreference
                  );
                }
              } else if (distinct) {
                if (!classExists) {
                  return [];
                } else {
                  return this.adapter.distinct(
                    className,
                    schema,
                    query,
                    distinct
                  );
                }
              } else if (pipeline) {
                if (!classExists) {
                  return [];
                } else {
                  return this.adapter.aggregate(
                    className,
                    schema,
                    pipeline,
                    readPreference
                  );
                }
              } else {
                return this.adapter
                  .find(className, schema, query, queryOptions)
                  .then(objects =>
                    objects.map(object => {
                      object = untransformObjectACL(object);
                      return filterSensitiveData(
                        isMaster,
                        aclGroup,
                        className,
                        protectedFields,
                        object
                      );
                    })
                  )
                  .catch(error => {
                    throw new Parse.Error(
                      Parse.Error.INTERNAL_SERVER_ERROR,
                      error
                    );
                  })
                  .then(findResponse => {
                    if (findResponse.length > 0 && schema.backendClass) {
                      //convertParseSchematToConnectorSchema()
                      if (auth.isMaster === true) {
                        auth.user = {
                          attributes: {
                            connectorUserName: schema.backendClass.masterUser,
                            connectorUserPassword:
                              schema.backendClass.masterPassword,
                          },
                        };
                      }
                      var backendBasedFieldsQuery = this.stripSpecialQueryKeys(
                        query
                      );
                      if (Object.keys(backendBasedFieldsQuery).length < 1) {
                        var connectorURI;
                        var compileConnectorURI = _.template(
                          schema.backendClass.find
                        );
                        var trimmedQuery = trimObjectKeys(
                          backendBasedFieldsQuery
                        ); // Just to avoid the pesky whitespaces causing _.template to bomb
                        try {
                          connectorURI = compileConnectorURI(trimmedQuery);
                        } catch (err) {
                          throw new Parse.Error(
                            Parse.Error.INTERNAL_SERVER_ERROR,
                            err.message
                          );
                        }

                        return ConnectorExecute(connectorURI, 'get', auth)
                          .then(connectorresponse => {
                            return this.filterConnectorCollectionByParseAccess(
                              schema,
                              findResponse,
                              connectorresponse
                            );
                          })
                          .then(
                            ([
                              filteredConnectorResponse,
                              connectorToParseObjectMap,
                            ]) => {
                              return this.convertConnectorDataToParseDataCollection(
                                className,
                                schema,
                                filteredConnectorResponse,
                                connectorToParseObjectMap
                              );
                            }
                          )
                          .catch(err => {
                            throw err;
                          });
                      } else {
                        return this.convertParseQueryToConnectorQuery(
                          className,
                          schema,
                          backendBasedFieldsQuery
                        ).then(connectorQuery => {
                          var connectorURI;
                          var trimmedQuery = trimObjectKeys(connectorQuery); // Just to avoid the pesky whitespaces causing _.template to bomb
                          if (
                            backendBasedFieldsQuery.objectId &&
                            Object.keys(backendBasedFieldsQuery).length === 1
                          ) {
                            var compileConnectorURI = _.template(
                              schema.backendClass.get
                            );

                            try {
                              connectorURI = compileConnectorURI(trimmedQuery);
                            } catch (err) {
                              throw new Parse.Error(
                                Parse.Error.INTERNAL_SERVER_ERROR,
                                err.message
                              );
                            }
                          } else {
                            Object.keys(trimmedQuery).forEach(key => {
                              global[key] = trimmedQuery[key];
                            });
                            connectorURI = eval(
                              '`' + schema.backendClass.query + '`;'
                            );
                            Object.keys(trimmedQuery).forEach(key => {
                              delete global[key];
                            });
                            //connectorURI = eval('`' + schema.backendClass.query + '`');
                            /*var finalstr = `https://slc12cqy:16690/siebel/v1.0/data/Expense/Expense?ViewMode=Personal&searchspec=(${queryString(
                              'AND',
                              "[${k}] = '${v}'",
                              query
                            )})`;*/
                            //console.log(connectorURI);
                          }

                          return ConnectorExecute(connectorURI, 'get', auth)
                            .then(connectorresponse => {
                              return this.filterConnectorCollectionByParseAccess(
                                schema,
                                findResponse,
                                connectorresponse
                              );
                            })
                            .then(
                              ([
                                filteredConnectorResponse,
                                connectorToParseObjectMap,
                              ]) => {
                                return this.convertConnectorDataToParseDataCollection(
                                  className,
                                  schema,
                                  filteredConnectorResponse,
                                  connectorToParseObjectMap
                                );
                              }
                            )
                            .catch(err => {
                              throw err;
                            });
                        });
                      }
                    } else {
                      return findResponse;
                    }
                  });
              }
            });
        });
    });
  }

  deleteSchema(className: string): Promise<void> {
    return this.loadSchema({ clearCache: true })
      .then(schemaController => schemaController.getOneSchema(className, true))
      .catch(error => {
        if (error === undefined) {
          return { fields: {} };
        } else {
          throw error;
        }
      })
      .then((schema: any) => {
        return this.collectionExists(className)
          .then(() => this.adapter.count(className, { fields: {} }))
          .then(count => {
            if (count > 0) {
              throw new Parse.Error(
                255,
                `Class ${className} is not empty, contains ${count} objects, cannot drop schema.`
              );
            }
            return this.adapter.deleteClass(className);
          })
          .then(wasParseCollection => {
            if (wasParseCollection) {
              const relationFieldNames = Object.keys(schema.fields).filter(
                fieldName => schema.fields[fieldName].type === 'Relation'
              );
              return Promise.all(
                relationFieldNames.map(name =>
                  this.adapter.deleteClass(joinTableName(className, name))
                )
              ).then(() => {
                return;
              });
            } else {
              return Promise.resolve();
            }
          });
      });
  }

  addPointerPermissions(
    schema: SchemaController.SchemaController,
    className: string,
    operation: string,
    query: any,
    aclGroup: any[] = []
  ) {
    // Check if class has public permission for operation
    // If the BaseCLP pass, let go through
    if (schema.testPermissionsForClassName(className, aclGroup, operation)) {
      return query;
    }
    const perms = schema.getClassLevelPermissions(className);
    const field =
      ['get', 'find'].indexOf(operation) > -1
        ? 'readUserFields'
        : 'writeUserFields';
    const userACL = aclGroup.filter(acl => {
      return acl.indexOf('role:') != 0 && acl != '*';
    });
    // the ACL should have exactly 1 user
    if (perms && perms[field] && perms[field].length > 0) {
      // No user set return undefined
      // If the length is > 1, that means we didn't de-dupe users correctly
      if (userACL.length != 1) {
        return;
      }
      const userId = userACL[0];
      const userPointer = {
        __type: 'Pointer',
        className: '_User',
        objectId: userId,
      };

      const permFields = perms[field];
      const ors = permFields.map(key => {
        const q = {
          [key]: userPointer,
        };
        // if we already have a constraint on the key, use the $and
        if (query.hasOwnProperty(key)) {
          return { $and: [q, query] };
        }
        // otherwise just add the constaint
        return Object.assign({}, query, {
          [`${key}`]: userPointer,
        });
      });
      if (ors.length > 1) {
        return { $or: ors };
      }
      return ors[0];
    } else {
      return query;
    }
  }

  addProtectedFields(
    schema: SchemaController.SchemaController,
    className: string,
    query: any = {},
    aclGroup: any[] = [],
    auth: any = {}
  ) {
    const perms = schema.getClassLevelPermissions(className);
    if (!perms) return null;

    const protectedFields = perms.protectedFields;
    if (!protectedFields) return null;

    if (aclGroup.indexOf(query.objectId) > -1) return null;
    if (
      Object.keys(query).length === 0 &&
      auth &&
      auth.user &&
      aclGroup.indexOf(auth.user.id) > -1
    )
      return null;

    let protectedKeys = Object.values(protectedFields).reduce(
      (acc, val) => acc.concat(val),
      []
    ); //.flat();
    [...(auth.userRoles || [])].forEach(role => {
      const fields = protectedFields[role];
      if (fields) {
        protectedKeys = protectedKeys.filter(v => fields.includes(v));
      }
    });

    return protectedKeys;
  }

  // TODO: create indexes on first creation of a _User object. Otherwise it's impossible to
  // have a Parse app without it having a _User collection.
  performInitialization() {
    const requiredUserFields = {
      fields: {
        ...SchemaController.defaultColumns._Default,
        ...SchemaController.defaultColumns._User,
      },
    };
    const requiredRoleFields = {
      fields: {
        ...SchemaController.defaultColumns._Default,
        ...SchemaController.defaultColumns._Role,
      },
    };

    const userClassPromise = this.loadSchema().then(schema =>
      schema.enforceClassExists('_User')
    );
    const roleClassPromise = this.loadSchema().then(schema =>
      schema.enforceClassExists('_Role')
    );

    const usernameUniqueness = userClassPromise
      .then(() =>
        this.adapter.ensureUniqueness('_User', requiredUserFields, ['username'])
      )
      .catch(error => {
        logger.warn('Unable to ensure uniqueness for usernames: ', error);
        throw error;
      });

    const emailUniqueness = userClassPromise
      .then(() =>
        this.adapter.ensureUniqueness('_User', requiredUserFields, ['email'])
      )
      .catch(error => {
        logger.warn(
          'Unable to ensure uniqueness for user email addresses: ',
          error
        );
        throw error;
      });

    const roleUniqueness = roleClassPromise
      .then(() =>
        this.adapter.ensureUniqueness('_Role', requiredRoleFields, ['name'])
      )
      .catch(error => {
        logger.warn('Unable to ensure uniqueness for role name: ', error);
        throw error;
      });

    const indexPromise = this.adapter.updateSchemaWithIndexes();

    // Create tables for volatile classes
    const adapterInit = this.adapter.performInitialization({
      VolatileClassesSchemas: SchemaController.VolatileClassesSchemas,
    });
    return Promise.all([
      usernameUniqueness,
      emailUniqueness,
      roleUniqueness,
      adapterInit,
      indexPromise,
    ]);
  }

  stripSpecialQueryKeys(query) {
    return _.fromPairs(
      Object.entries(query).filter(entry => !isSpecialQueryKey(entry[0]))
    );
  }
  parseUserIdToConnectorUserName(userId): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema('_User', true);
      })
      .then(userschema =>
        this.adapter.find('_User', userschema, { _id: userId }, {})
      )
      .then(user => {
        return Promise.resolve(user[0].connectorUserName);
      })
      .catch(err => {
        throw err;
      });
  }

  parsePointerObjectIdToConnectorField(
    className,
    pointerId,
    connectorFieldName
  ): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema(className, true);
      })
      .then(classSchema =>
        this.adapter.find(className, classSchema, { _id: pointerId }, {})
      )
      .then(record => {
        return Promise.resolve(record[0][connectorFieldName]);
      })
      .catch(err => {
        throw err;
      });
  }

  connectorUserNameToParseUserId(userName): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema('_User', true);
      })
      .then(userschema =>
        this.adapter.find(
          '_User',
          userschema,
          { connectorUserName: userName },
          {}
        )
      )
      .then(user => {
        return Promise.resolve(user[0].objectId);
      })
      .catch((/*err*/) => {
        return Promise.resolve('notuser');
      });
  }

  connectorFieldToParsePointerObjectId(
    className,
    connectorField,
    connectorFieldValue
  ): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema(className, true);
      })
      .then(pointerSchema => {
        var searchSpec = {};
        searchSpec[connectorField] = connectorFieldValue;
        return this.adapter.find(className, pointerSchema, searchSpec, {});
      })
      .then(record => {
        return Promise.resolve(record[0].objectId);
      })
      .catch((/*err*/) => {
        return Promise.resolve('notInParseDB');
      });
  }

  connectorIdToParseObjectId(className, connectorId): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema(className, true);
      })
      .then(classSchema =>
        this.adapter.find(
          className,
          classSchema,
          { connectorId: connectorId },
          {}
        )
      )
      .then(object => {
        return Promise.resolve(object[0].objectId);
      })
      .catch((/*err*/) => {
        return Promise.resolve(null);
      });
  }

  parseObjectIdToConnectorId(className, objectId): Promise<string> {
    return this.loadSchema()
      .then(schemaController => {
        return schemaController.getOneSchema(className, true);
      })
      .then(classSchema =>
        this.adapter.find(className, classSchema, { objectId: objectId }, {})
      )
      .then(object => {
        return Promise.resolve(object[0].connectorId);
      })
      .catch((/*err*/) => {
        return Promise.resolve('this record was not created through this app');
      });
  }

  /*
  getParseIdFromConnectorId(schema, connectorId):Promise<string>{
    return this.adapter.find('_User', userschema, { connectorUserName: userName }, {}))
      .then((user) => {
        return Promise.resolve(user[0].objectId);
      }).
      catch((err) => {
        return Promise.resolve("notuser");
      })
  }
*/
  convertParseDataToConnectorData(schema, object, parseUpdateObject) {
    return new Promise(resolve => {
      var nonBackendFields;
      if (parseUpdateObject) {
        nonBackendFields = ['ACL', 'createdAt', 'updatedAt'];
      } else {
        nonBackendFields = ['ACL', 'createdAt', 'updatedAt', 'objectId'];
      }
      var backendfieldsObject = _.fromPairs(
        Object.entries(object).filter(
          entry => nonBackendFields.indexOf(entry[0]) === -1
        )
      );

      var promises = Object.entries(backendfieldsObject).map(
        (entry): Promise<any> => {
          var key, value;
          key = schema.fields[entry[0]].backendField;
          var transformation = schema.fields[entry[0]].transformation;
          var type = schema.fields[entry[0]].type;
          if (transformation) {
            if (type === 'Pointer') {
              if (transformation === 'connectorUserName') {
                return this.parseUserIdToConnectorUserName(
                  entry[1].objectId
                ).then(connectorUserName => {
                  value = connectorUserName;
                  return Promise.resolve([key, value]);
                });
              } else {
                return this.parsePointerObjectIdToConnectorField(
                  entry[1].className,
                  entry[1].objectId,
                  transformation
                ).then(connectorFieldValue => {
                  value = connectorFieldValue;
                  return Promise.resolve([key, value]);
                });
              }
            } else if (type === 'Date') {
              if (transformation === 'Short Date') {
                const date = new Date(entry[1].iso);
                const year = date.getFullYear();
                const month = (1 + date.getMonth()).toString().padStart(2, '0');
                const day = date
                  .getDate()
                  .toString()
                  .padStart(2, '0');

                value = month + '/' + day + '/' + year;
                return Promise.resolve([key, value]);
                //return [key,value];
              }
            } else if (parseUpdateObject) {
              if (entry[0] === 'objectId') {
                value = parseUpdateObject.connectorId;
                return Promise.resolve([key, value]);
              }
            }
          } else {
            value = entry[1];
            return Promise.resolve([key, value]);
            //return [key,value];
          }
        }
      );
      Promise.all(promises).then(entryMap => {
        var connectorPayload = _.fromPairs(entryMap);
        return resolve(connectorPayload);
      });
    });
  }

  convertConnectorDataToParseData(
    className,
    schema,
    connectorObject,
    parseLocalObject
  ) {
    return new Promise(resolve => {
      const exclusionFields = ['connectorId'];
      var parseFieldsObject = _.fromPairs(
        Object.entries(connectorObject).filter(
          entry => exclusionFields.indexOf(entry[0]) === -1
        )
      );
      //Remove this - not needed any more as all non matching parse Local records have already been filtered
      //var parseId;
      this.connectorIdToParseObjectId(className, connectorObject.Id)
        .then(
          parseObjectId => {
            if (parseObjectId) {
              //parseId = parseObjectId;
              //return resolve(parseObject);
            } else {
              return resolve(null);
            }
          } //Remove this - not needed any more as all non matching parse Local records have already been filtered
        )
        .then(() => {
          var promises = Object.entries(parseFieldsObject)
            .filter(entry => {
              return Object.keys(schema).indexOf(entry[0]) > -1;
            })
            .map(
              (entry): Promise<any> => {
                var key, value;

                key = schema[entry[0]].parseField;
                var transformation = schema[entry[0]].transformation;
                var type = schema[entry[0]].type;
                if (transformation) {
                  if (type === 'Pointer') {
                    var targetClass = schema[entry[0]].targetClass;
                    if (transformation === 'connectorUserName') {
                      return this.connectorUserNameToParseUserId(entry[1]).then(
                        parseUserId => {
                          value = {
                            __type: 'Pointer',
                            className: '_User',
                            objectId: parseUserId,
                          };
                          return Promise.resolve([key, value]);
                        }
                      );
                    } else {
                      return this.connectorFieldToParsePointerObjectId(
                        targetClass,
                        transformation,
                        entry[1]
                      ).then(parseObjectId => {
                        value = {
                          __type: 'Pointer',
                          className: targetClass,
                          objectId: parseObjectId,
                        };
                        return Promise.resolve([key, value]);
                      });
                    }
                  } else if (type === 'Date') {
                    if (transformation === 'Short Date') {
                      const date = new Date(entry[1]);
                      value = {
                        __type: 'Date',
                        iso: date.toISOString(),
                      };
                      return Promise.resolve([key, value]);
                      //return [key,value];
                    }
                  } else {
                    value = entry[1];
                    return Promise.resolve([key, value]);
                  }
                } else {
                  value = entry[1];
                  return Promise.resolve([key, value]);
                  //return [key,value];
                }
              }
            );

          Promise.all(promises)
            .then(entryMap => {
              var parseResponsePayload = _.fromPairs(entryMap);
              return parseResponsePayload;
            })
            .then(parseObject => {
              parseObject.objectId = parseLocalObject.objectId;
              parseObject.updatedAt = parseLocalObject.updatedAt;
              parseObject.createdAt = parseLocalObject.createdAt;
              return resolve(parseObject);
            });
        });
    });
  }

  convertConnectorDataToParseDataCollection(
    className,
    schema,
    connectorObjectCollection,
    connectorToParseObjectMap
  ) {
    return new Promise(resolve => {
      var key, value;
      var invertedSchema;
      var invertedSchemaFieldsEntries = Object.entries(schema.fields)
        .filter(entry => {
          return entry[1].backendField;
        })
        .map(entry => {
          key = entry[1].backendField;
          value = entry[1];
          value.parseField = entry[0];
          return [key, value];
        });
      invertedSchema = _.fromPairs(invertedSchemaFieldsEntries);

      var promises = connectorObjectCollection.map(
        (object): Promise<any> => {
          return this.convertConnectorDataToParseData(
            className,
            invertedSchema,
            object,
            connectorToParseObjectMap.get(object.Id)
          ).then(convertedObject => {
            return Promise.resolve(convertedObject);
          });
        }
      );

      Promise.all(promises).then(parseObjectCollection => {
        /*parseObjectCollection.results = [];
        parseObjectCollection.results.push(convertedParseObject)*/
        return resolve(parseObjectCollection.filter(entry => entry != null));
        //return resolve(parseObjectCollection);
      });
    });
  }

  convertParseQueryToConnectorQuery(className, schema, backendfieldsQuery) {
    return new Promise(resolve => {
      var promises = Object.entries(backendfieldsQuery).map(
        (entry): Promise<any> => {
          var key, value;
          key = schema.fields[entry[0]].backendField;
          //special treatment for ObjectId. Can remove.
          if (key === 'Id') {
            return this.parseObjectIdToConnectorId(className, entry[1]).then(
              connectorId => {
                value = connectorId;
                return Promise.resolve([key, value]);
              }
            );
          }
          var transformation = schema.fields[entry[0]].transformation;
          var type = schema.fields[entry[0]].type;
          if (transformation) {
            if (type === 'Pointer') {
              if (transformation === 'connectorUserName') {
                return this.parseUserIdToConnectorUserName(
                  entry[1].objectId
                ).then(connectorUserName => {
                  value = connectorUserName;
                  return Promise.resolve([key, value]);
                });
              } else {
                return this.parsePointerObjectIdToConnectorField(
                  entry[1].className,
                  entry[1].objectId,
                  transformation
                ).then(connectorFieldValue => {
                  value = connectorFieldValue;
                  return Promise.resolve([key, value]);
                });
              }
            } else if (type === 'Date') {
              if (transformation === 'Short Date') {
                const date = new Date(entry[1].iso);
                const year = date.getFullYear();
                const month = (1 + date.getMonth()).toString().padStart(2, '0');
                const day = date
                  .getDate()
                  .toString()
                  .padStart(2, '0');

                value = month + '/' + day + '/' + year;
                return Promise.resolve([key, value]);
                //return [key,value];
              }
            }
          } else {
            value = entry[1];
            return Promise.resolve([key, value]);
            //return [key,value];
          }
        }
      );
      Promise.all(promises).then(entryMap => {
        var connectorPayload = _.fromPairs(entryMap);
        return resolve(connectorPayload);
      });
    });
  }

  filterConnectorCollectionByParseAccess(
    schema,
    findResponse,
    connectorObjectCollection
  ) {
    var connectorObjectToParseObjectMap = new Map();
    var filteredConnectorObjectCollection = connectorObjectCollection.data[
      schema.backendClass.collectionKey
    ].filter(
      object =>
        findResponse.filter(record => {
          if (object.Id === record['connectorId']) {
            connectorObjectToParseObjectMap.set(object.Id, record);
            return true;
          } else {
            return false;
          }
        }).length > 0
    );
    return [filteredConnectorObjectCollection, connectorObjectToParseObjectMap];
  }

  static _validateQuery: any => void;
}

module.exports = DatabaseController;
// Expose validateQuery for tests
module.exports._validateQuery = validateQuery;
