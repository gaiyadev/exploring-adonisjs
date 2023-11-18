import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { rules, schema, ValidationException } from '@ioc:Adonis/Core/Validator'
import User from 'App/Models/User'
import Logger from '@ioc:Adonis/Core/Logger'
import Hash from '@ioc:Adonis/Core/Hash'

export default class UsersController {
  public async signUp({ request, response }: HttpContextContract) {
    try {
      const newUserSchema = schema.create({
        firstName: schema.string({}, [rules.alpha()]),
        lastName: schema.string({}, [rules.alpha()]),
        email: schema.string({}, [
          rules.email(),
          rules.unique({ table: 'users', column: 'email' }),
        ]),
        password: schema.string({}, [rules.confirmed('confirmPassword'), rules.minLength(4)]),
      })

      const payload = await request.validate({
        schema: newUserSchema,
        messages: {
          'required': '{{ field }} is required',
          'minLength': '{{ field }} is too short',
          'confirmed': '{{field}} not match',
          'email': '{{ field }} address must be valid',
          'email.unique': '{{ field }} already in use',
          'alpha': '{{ field }} must be letters',
        },
      })
      const user = await User.create(payload)
      return response.status(201).json({
        message: 'User created successfully',
        data: { id: user.id, email: user.email },
      })
    } catch (err) {
      if (err instanceof ValidationException) {
        return response.status(400).json({ message: err['messages'] })
      }
      Logger.error(err)
      return response.status(500).json({ message: 'Internal server error' })
    }
  }

  public async login({ auth, request, response }: HttpContextContract) {
    const email = request.input('email')
    const password = request.input('password')

    try {
      // Retrieve the user by email from the database
      const user = await User.findBy('email', email)

      if (!user) {
        return response.unauthorized('Invalid credentials')
      }

      // Verify the user-provided password with the stored hashed password
      const isPasswordValid = await Hash.verify(user.password, password)

      if (isPasswordValid) {
        // Password is valid, authenticate the user and return the token
        const token = await auth.use('api').attempt(email, password, {
          expiresIn: '1d',
        })
        return { data: { id: user.id, email: user.email }, token }
      } else {
        // Password is invalid
        return response.unauthorized('Invalid credentials')
      }
    } catch (error) {
      // Handle other errors
      console.error(error)
      return response.internalServerError('Internal server error')
    }
  }
}
