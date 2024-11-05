const mongoose = require('mongoose')
const chalk = require('chalk')
const {PrismaClient} = require('@prisma/client')
const prisma = new PrismaClient()

const VulnerabilityPattern = require('../data-models/vulnerability-pattern')

require('dotenv').config()


module.exports = {
  establishDbConnection: async() => {
    try {
      await prisma.$connect()
      return true
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  },
  // establishDbConnection: () => {
  //   const uri = process.env.MONGODB_ATLAS_URI
  //   return mongoose.connect(uri)
  //     .then(() => {
  //       return true
  //     })
  //     .catch((err) => {
  //       console.log(chalk.red(err))
  //       return false
  //     })
  // },

  isDbConnected: async() => {
    try {
      await prisma.$queryRaw`SELECT 1`;
      return true
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  },
  // isDbConnected: () => {
  //   const state = mongoose.connection.readyState
  //   switch (state) {
  //     case 0:
  //       console.log(chalk.red('Database disconnected.'))
  //       return false
  //     case 1:
  //       // console.log(chalk.greenBright('Database connected.'))
  //       return true
  //     case 2:
  //       console.log(chalk.greenBright('Database is connecting...'))
  //       return false
  //     case 3:
  //       console.log(chalk.red('Database is disconnecting...'))
  //       return false
  //   }
  // },

  closeDbConnection: async() => {
    try {
      await prisma.$disconnect()
      return true
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  },
  // closeDbConnection: () => {
  //   return mongoose.disconnect()
  //     .then(() => {
  //       return true
  //     })
  //     .catch((err) => {
  //       console.log(chalk.red('Close database connection error: ', err))
  //       return false
  //     })
  // },

  retrievePatterns: async(id) => {
    // console.log(id, "id in retrievePatterns masuk")
    try {
      const vulnerabilities = await prisma.vulnerabilityPatterns.findMany({
        where: {
          vulnerabilityId: id,
        },
        select: {
          patterns: true,
        }
      });
      // return vulnerability?.patterns || {};
      const patternsArray = vulnerabilities.flatMap(vulnerability => vulnerability.patterns);
      return patternsArray;
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  },
  // retrievePatterns: (id) => {
  //   let patterns = {}
  //   return VulnerabilityPattern.find({ vulnerabilityId: id })
  //     .then(vulnerabilities => {
  //       vulnerabilities.forEach(vulnerability => {
  //         patterns = vulnerability.patterns
  //       })
  //       return patterns
  //     })
  //     .catch(err => {
  //       return console.log(chalk.red(err))
  //     })
  // },

  retrieveAllPatterns: async() => {
    try {
      const vulnerabilities = await prisma.vulnerabilityPatterns.findMany({
        select: {
          vulnerabilityame: true,
          patterns: true,
        }
      });
      // const vulnerabilitiesMap = {};
      // vulnerabilities.forEach(vulnerability => {
      //   vulnerabilitiesMap[vulnerability.vulnerabilityName] = vulnerability.patterns;
      // });
      // return vulnerabilitiesMap;
      return vulnerabilities.reduce((acc, curr) => {
        acc[curr.vulnerabilityName] = curr.patterns;
        return acc;
      }, {});
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  },
  // retrieveAllPatterns: () => {
  //   const vulnerabilitiesMap = {}
  //   return VulnerabilityPattern.find({})
  //     .then(vulnerabilities => {
  //       vulnerabilities.forEach(vulnerability => {
  //         vulnerabilitiesMap[vulnerability.vulnerabilityName] = vulnerability.patterns
  //       })
  //       return vulnerabilitiesMap
  //     })
  //     .catch(err => {
  //       return console.log(chalk.red(err))
  //     })
  // },

  retrieveVulnerabilityInfo: async(id) => {
    try {
      const vulnerability = await prisma.vulnerabilityPatterns.findUnique({
        where: {
          vulnerabilityId: id,
        },
        select: {
          vulnerabilityName: true,
          severity: true,
          swc_code: true,
          mitigation: true,
        }
      });
      return {
        name: vulnerability?.vulnerabilityName || '',
        severity: vulnerability?.severity || '',
        swcCode: vulnerability?.swc_code || '',
        mitigations: vulnerability?.mitigation || '',
      };
    } catch (err) {
      console.log(chalk.red(err))
      return false
    }
  }
  // retrieveVulnerabilityInfo: (id) => {
  //   return VulnerabilityPattern.findOne({ vulnerabilityId: id })
  //     .then((vulnerability) => {
  //       const vulnerabilityInfo = {
  //         name: vulnerability.vulnerabilityName,
  //         severity: vulnerability.severity,
  //         swcCode: vulnerability.swc_code,
  //         mitigations: vulnerability.mitigation
  //       }
  //       return vulnerabilityInfo
  //     })
  //     .catch((error) => {
  //       return console.log(chalk.red(error))
  //     })
  // }
}
