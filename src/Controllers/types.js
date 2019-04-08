export type LoadSchemaOptions = {
  clearCache: boolean,
};

export type SchemaField = {
  type: string,
  targetClass?: ?string,
  backendField?: ?string,
  transformation?: ?string,
};

export type SchemaFields = { [string]: SchemaField };

export type BackendClass = {
  base: RESTRequestDetails,
  find: string,
  query: string,
  get: string,
  update: string,
  collectionKey: string,
  masterUser: string,
  masterPassword: string,
};

export type RESTRequestDetails = {
  uri: string,
  method: string,
};

export type Schema = {
  className: string,
  fields: SchemaFields,
  classLevelPermissions: ClassLevelPermissions,
  indexes?: ?any,
  backendClass?: ?BackendClass,
};

export type ClassLevelPermissions = {
  find?: { [string]: boolean },
  count?: { [string]: boolean },
  get?: { [string]: boolean },
  create?: { [string]: boolean },
  update?: { [string]: boolean },
  delete?: { [string]: boolean },
  addField?: { [string]: boolean },
  readUserFields?: string[],
  writeUserFields?: string[],
  protectedFields?: { [string]: string[] },
};
