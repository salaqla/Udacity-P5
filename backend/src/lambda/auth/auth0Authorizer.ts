import { CustomAuthorizerEvent, CustomAuthorizerResult } from "aws-lambda";
import "source-map-support/register";
import { verify} from "jsonwebtoken";
import { createLogger } from "../../utils/logger";
import { JwtPayload } from "../../auth/JwtPayload";
const logger = createLogger("auth");

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJXxeqUko05WrGMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi00a3R5OGNlaS5hdXRoMC5jb20wHhcNMTkxMjEwMDk0NjQ0WhcNMzMw
ODE4MDk0NjQ0WjAhMR8wHQYDVQQDExZkZXYtNGt0eThjZWkuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2SyONMPtPT7ADkwdvoi8i7y2
cdb13vnqYS+Y50dnneytmCgK1nhFULijWs5+CmqAdYV1CjOQZIl1iqGIUOP7++fS
OUIqKhUwHup8NXRIZND7hU07IVEsj4yLT8M0po0WP2D+7QBfnFJXAlo1T8xihXZn
+bEtBmE7t3iQLBh+AvfvNYcP1EXl//mB6MNt8XQQRe2/RWwNhbgErnNiJXOiha9/
YDdiJn3XqFeL1qvumP3TwhlKPuWcej/4irKRu91YFWXz5IV9NPlzrKPzz4HlVlQp
kuLBgwuKuwc5fRnpUjjV0/niX0fEcnE3cZKKHGbh/imxk5e5UNEnuTBgdfJWaQID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRAb63GgfbVHwV02nli
RGycybsr+zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAJai6lEw
wXmGaUlVtto7L4Ly3yON6e+TDdCnNwNnatjtdjZTcz0FPG7/43V3gJLzVJLXTFPW
i2CweBNLYEnzRWav2rRy5UddsAIGlCVSUw2ELvrShLztdBp4Pw0i6hBfWoxuCKvX
veJ0pagbiPCH+zzvfCPRLPay4JY9lhpN+Lx2LaySE1FT3CCYGbrVmrb7ocMuJTKP
ENyLN2jUykm4IlgH7PFglUYHF19n4/aDJbJ2BVa1vFOTJZEQ9YecFfevDajOwWA9
7dEd3/uVLnMtctvCf8Mlu1IvOl85wdrEjETB5POce7d86fDphrIpp+wDkChyOkQR
IxyQlE2gzpMqesw=
-----END CERTIFICATE-----

`;
export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info("Authorizing a user", event.authorizationToken);
  try {
    const jwtToken = await verifyToken(event.authorizationToken);
    logger.info("User was authorized", jwtToken);

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: "*"
          }
        ]
      }
    };
  } catch (e) {
    logger.error("User not authorized", { error: e.message });

    return {
      principalId: "user",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Deny",
            Resource: "*"
          }
        ]
      }
    };
  }
};

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader);
  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ["RS256"] }) as JwtPayload;
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error("No authentication header");

  if (!authHeader.toLowerCase().startsWith("bearer "))
    throw new Error("Invalid authentication header");

  const split = authHeader.split(" ");
  const token = split[1];

  return token;
}
