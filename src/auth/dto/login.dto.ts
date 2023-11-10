import { OmitType } from "@nestjs/mapped-types";
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class RegisterDto {

    @IsString()
    name: string;

    @IsEmail()
    email: string;

    @IsNotEmpty()
    @MinLength(6)
    password: string;
}

export class LoginDto extends OmitType(RegisterDto, ['name']) {}