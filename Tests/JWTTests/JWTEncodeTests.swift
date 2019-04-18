import XCTest
import JWT


class JWTEncodeTests: XCTestCase {
  func testEncodingJWT() {
    let payload = ["name": "Kyle"] as Payload
    let jwt = JWT.encode(claims: payload, algorithm: .hs256("secret".data(using: .utf8)!))

    let expected = [
      // { "alg": "HS256", "typ": "JWT" }
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.zxm7xcp1eZtZhp4t-nlw09ATQnnFKIiSN83uG8u6cAg",

      // {  "typ": "JWT", "alg": "HS256" }
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiS3lsZSJ9.4tCpoxfyfjbUyLjm9_zu-r52Vxn6bFq9kp6Rt9xMs4A",
    ]

    XCTAssertTrue(expected.contains(jwt))
  }

  func testEncodingWithBuilder() {
    let algorithm = Algorithm.hs256("secret".data(using: .utf8)!)
    let jwt = JWT.encode(algorithm) { builder in
      builder.issuer = "fuller.li"
    }

    XCTAssert(jwt == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.d7B7PAQcz1E6oNhrlxmHxHXHgg39_k7X7wWeahl8kSQ"
        || jwt == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmdWxsZXIubGkifQ.x5Fdll-kZBImOPtpT1fZH_8hDW01Ax3pbZx_EiljoLk")
  }

  func testEncodingClaimsWithHeaders() {
    let algorithm = Algorithm.hs256("secret".data(using: .utf8)!)
    let jwt = JWT.encode(claims: ClaimSet(), algorithm: algorithm, headers: ["kid": "x"])

    XCTAssert(jwt == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IngifQ.e30.ddEotxYYMMdat5HPgYFQnkHRdPXsxPG71ooyhIUoqGA"
        || jwt == "eyJraWQiOiJ4IiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.e30.5KqN7N5a7Cfbe2eKN41FJIfgMjcdSZ7Nt16xqlyOeMo"
        || jwt == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IngifQ.e30.5t6a61tpSXFo5QBHYCnKAz2mTHrW9kaQ9n_b7e-jWw0"
        || jwt == "eyJhbGciOiJIUzI1NiIsImtpZCI6IngiLCJ0eXAiOiJKV1QifQ.e30.xiT6fWe5dWGeuq8zFb0je_14Maa_9mHbVPSyJhUIJ54"
        || jwt == "eyJ0eXAiOiJKV1QiLCJraWQiOiJ4IiwiYWxnIjoiSFMyNTYifQ.e30.DG5nmV2CVH6mV_iEm0xXZvL0DUJ22ek2xy6fNi_pGLc"
        || jwt == "eyJraWQiOiJ4IiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.e30.h5ZvlqECBIvu9uocR5_5uF3wnhga8vTruvXpzaHpRdA")
  }
}
