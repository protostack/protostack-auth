import * as mongoose from 'mongoose';
import { ObjectId } from 'bson';

export interface IRole extends mongoose.Document {
  name: string;
  permissions: string[];
  inherits: string[];
  meta: object;
}

const roleSchema = new mongoose.Schema({
  name: { index: true, required: true, type: String, unique: true },
  permissions: [{ type: ObjectId, ref: 'permissions' }],
  inherits: [{ type: ObjectId, ref: 'roles' }],
  meta: Object,
});

export default roleSchema;
