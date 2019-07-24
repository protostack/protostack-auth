import * as mongoose from 'mongoose';

export interface IPermission extends mongoose.Document {
  name: string;
  meta: object;
}

const permissionSchema = new mongoose.Schema({
  name: { index: true, required: true, type: String, unique: true },
  meta: Object,
});

export default permissionSchema;
