# 2026_rapa_securecoding

자료 출처: 
https://s3.ap-northeast-2.amazonaws.com/inflearnattachment/boanproject/powershell/powershell_course.pdf




return (req: Request, res: Response, next: NextFunction) => {
  verifyPreLoginChallenges(req)

  const email = req.body.email || ''
  const passwordHash = security.hash(req.body.password || '')

  models.sequelize.query(
    `
    SELECT * FROM Users
    WHERE email = :email
      AND password = :password
      AND deletedAt IS NULL
    `,
    {
      replacements: {
        email,
        password: passwordHash
      },
      model: UserModel,
      plain: true
    }
  )
  .then((authenticatedUser) => {
    const user = utils.queryResultToJson(authenticatedUser)

    if (user.data?.id && user.data.totpSecret !== '') {
      res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.data.id,
            type: 'password_valid_needs_second_factor_token'
          })
        }
      })
    } else if (user.data?.id) {
      afterLogin(user as any, res, next)
    } else {
      res.status(401).send(res.__('Invalid email or password.'))
    }
  })
  .catch((error: Error) => {
    next(error)
  })
}
