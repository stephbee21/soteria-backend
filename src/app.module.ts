import { Module } from '@nestjs/common';
// import { UsersController } from './users/users.controller';
// import { AuthController } from './auth/auth.controller';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    AuthModule,   // <-- must be imported
    UsersModule,  // <-- if your AuthService depends on it
  ],
  providers: [],
})
export class AppModule {}
