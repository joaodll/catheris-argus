import { describe, expect, it } from 'vitest'
import { apiPasswordProblem, newPasswordProblem } from './passwords'

describe('newPasswordProblem', () => {
  it('asks for length first, then the username, then the repetition', () => {
    expect(newPasswordProblem('short', 'short', 'maria')).toEqual({ field: 'new', message: 'Use at least 12 characters.' })
    expect(newPasswordProblem('Maria.Silva1', 'Maria.Silva1', 'maria.silva1')?.message).toBe("It can't be your username.")
    expect(newPasswordProblem('a long passphrase', 'a long passphrasE', 'maria')).toEqual({ field: 'repeat', message: "The passwords don't match." })
    expect(newPasswordProblem('a long passphrase', 'a long passphrase', 'maria')).toBeNull()
  })

  it('takes no composition rules: a phrase of plain words is fine', () => {
    expect(newPasswordProblem('correct horse battery', 'correct horse battery', 'admin')).toBeNull()
  })
})

describe('apiPasswordProblem', () => {
  it('puts the API refusal under the field it names', () => {
    expect(apiPasswordProblem('current_password: your current password is wrong')).toEqual({
      field: 'current',
      message: 'Your current password is wrong.',
    })
    expect(apiPasswordProblem('new_password: choose a password other than the current one').field).toBe('new')
    expect(apiPasswordProblem('too many attempts')).toEqual({ field: 'new', message: 'too many attempts' })
  })
})
