import * as mongoose from 'mongoose';

export interface IUser extends mongoose.Document {
  email: string;
  password: string;
  role: string;
  created: Date;
  twoFASecret?: string;
}

const userSchema = new mongoose.Schema({
  email: { index: true, required: true, type: String, unique: true },
  password: { type: String, required: true },
  role: String,
  twoFASecret: String,
  created: { type: Date, default: Date.now() },
});

export default userSchema;
