import * as mongoose from 'mongoose';

export type RoleModel = mongoose.Document & {
  name: String,
  description: String,
  permissions: String
};

const roleSchema = new mongoose.Schema({
  name: String,
  description: String,
  permissions : [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }],
}, { timestamps: true });

const Role = mongoose.model('Role', roleSchema);

Role.collection.createIndex('name', {
  unique: true,
  partialFilterExpression: {
    'name': {
      $type: 'string'
    }
  }
});

export default Role;