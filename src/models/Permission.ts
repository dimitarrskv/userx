import * as mongoose from 'mongoose';

export type PermissionModel = mongoose.Document & {
  name: string,
  actions: String[]
};

const permissionSchema = new mongoose.Schema({
  name: String,
  actions: Array
}, { timestamps: true });

const Permission = mongoose.model('Permission', permissionSchema);

Permission.collection.createIndex('name', {
  unique: true,
  partialFilterExpression: {
    'name': {
      $type: 'string'
    }
  }
});

export default Permission;