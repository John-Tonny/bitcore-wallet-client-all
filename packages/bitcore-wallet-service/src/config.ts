let dbUrl = 'mongodb://localhost:27017/bws';
if (process.env.DB_URL) {
  dbUrl = process.env.DB_URL + '/bws';
}
module.exports = {
  basePath: '/bws/api',
  disableLogs: false,
  port: 3232,

  // john
  ignoreRateLimiter: true,

  // Uncomment to make BWS a forking server
  // cluster: true,

  // Uncomment to set the number or process (will use the nr of availalbe CPUs by default)
  // clusterInstances: 4,

  // https: true,
  // privateKeyFile: 'private.pem',
  // certificateFile: 'cert.pem',
  ////// The following is only for certs which are not
  ////// trusted by nodejs 'https' by default
  ////// CAs like Verisign do not require this
  // CAinter1: '', // ex. 'COMODORSADomainValidationSecureServerCA.crt'
  // CAinter2: '', // ex. 'COMODORSAAddTrustCA.crt'
  // CAroot: '', // ex. 'AddTrustExternalCARoot.crt'

  storageOpts: {
    mongoDb: {
      uri: dbUrl
      // uri:  process.env.DB_URL + '/bws' || 'mongodb://localhost:27017/bws'
    }
  },
  messageBrokerOpts: {
    //  To use message broker server, uncomment this:
    messageBrokerServer: {
      url: 'http://localhost:3380'
    }
  },
  blockchainExplorerOpts: {
    // john
    vcl: {
      livenet: {
        url: 'http://localhost:3000'
      } /*,
      testnet: {
        url: 'http://localhost:3100'
      }*/
    },
    socketApiKey: 'L2mPTvucM9CNvUU6MaJwUpYiLEDN9TLa3g3Fv4Fu8CnZob4ADZdJ'
  },
  pushNotificationsOpts: {
    templatePath: 'templates',
    defaultLanguage: 'en',
    // john
    defaultUnit: 'vcl',
    // defaultUnit: 'btc',
    subjectPrefix: '',
    pushServerUrl: 'https://fcm.googleapis.com/fcm',
    authorizationKey: 'You_have_to_put_something_here'
  },
  fiatRateServiceOpts: {
    defaultProvider: 'BitPay',
    fetchInterval: 60 // in minutes
  },
  maintenanceOpts: {
    maintenanceMode: false
  },
  staticRoot: '/tmp/static'
  // simplex: {
  //   sandbox: {
  //     apiKey: 'simplex_sandbox_api_key_here',
  //     api: 'https://sandbox.test-simplexcc.com',
  //     appProviderId: 'simplex_provider_id_here'
  //   },
  //   production: {
  //     apiKey: 'simplex_production_api_key_here',
  //     api: 'https://backend-wallet-api.simplexcc.com',
  //     appProviderId: 'simplex_provider_id_here'
  //   }
  // },
  // To use email notifications uncomment this:
  // emailOpts: {
  //  host: 'localhost',
  //  port: 25,
  //  ignoreTLS: true,
  //  subjectPrefix: '[Wallet Service]',
  //  from: 'wallet-service@bitcore.io',
  //  templatePath: 'templates',
  //  defaultLanguage: 'en',
  //  defaultUnit: 'btc',
  //  publicTxUrlTemplate: {
  //    btc: {
  //      livenet: 'https://insight.bitcore.io/#/BTC/mainnet/tx/{{txid}}',
  //      testnet: 'https://insight.bitcore.io/#/BTC/testnet/tx/{{txid}}',
  //    },
  //    bch: {
  //      livenet: 'https://insight.bitcore.io/#/BCH/mainnet/tx/{{txid}}',
  //      testnet: 'https://insight.bitcore.io/#/BCH/testnet/tx/{{txid}}',
  //    }
  //  },
  // },
  // To use sendgrid:
  // const sgMail = require('@sendgrid/mail');
  // sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  //
  //
  // //then add:
  // mailer: sgMail,
};
