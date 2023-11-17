import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/auth.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto, RegisterDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';

@Injectable()
export class AuthService {
  
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createAuthDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createAuthDto;
      const salt = await bcryptjs.genSalt(10);
      const hashedPassword = bcryptjs.hashSync(password, salt);

      const newUser = new this.userModel({
        ...userData,
        password: hashedPassword,
      });
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createAuthDto.email} already exists`);
      }
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);

    return {
      user,
      token: this.getJwtToken({ id: user._id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email }).select('+password');

    if (!user) {
      throw new UnauthorizedException(`Invalid credentials in email`);
    }

    const isPasswordMatch = bcryptjs.compareSync(password, user.password);

    if (!isPasswordMatch) {
      throw new UnauthorizedException(`Invalid credentials in password`);
    }

    const { password:_, ...userFound } = user.toJSON();

    return {
      user: userFound,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  async findAll(): Promise<User[]> {
    return await this.userModel.find();
  }

  async findOne(id: string) {
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();

    return rest;
  }

  getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
