import * as mongoose from 'mongoose';

export interface IUser extends mongoose.Document {
  email: string;
  password: string;
  role: string;
  created: Date;
  twoFASecret?: string;
  twoFAEnabled?: boolean;
  passwordResetToken?: string;
  passwordResetExpiry?: Date;
}

const userSchema = new mongoose.Schema({
  email: { index: true, required: true, type: String, unique: true },
  password: { type: String, required: true },
  role: String,
  created: { type: Date, default: Date.now() },
  twoFASecret: String,
  twoFAEnabled: Boolean,
  passwordResetToken: { type: String, unique: true },
  passwordResetExpiry: Date,
});

export default userSchema;
