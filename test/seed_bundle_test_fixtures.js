export default {
  "success": [
    {
      "desc": "two-pass-generated-by-javascript",
      "cipher": "k6VoY3NiMJKWonB3xBDsEEGX8xbw7lBOyJQGFgPLzSAAAcQYU1CZvyjFB6PQJsShIUm8i-EScti04acYxDGVBvUz_87xdqZDb3RubrJ1YBVQDDmr0z3_Bf07O0PgJ2Bg08KD8gpIpirSt3fKueVolqJwd8QQSuaipI0rXCtalErGLAWFGs0gAAHEGMfI7d3qTDyvGy0VUwUpDRuydUEHIH2WEMQxrlEtQbRHniKmNfdm0c9v11ZZRkZPIx1kE28il57A6vE0uE7kfUiCwIW0y0dhlPeqzMQBgA",
      "unlock": [
        {
          "type": "pwHash",
          "passphrase": "zombies1"
        },
        {
          "type": "pwHash",
          "passphrase": "zombies2"
        }
      ],
      "signPubKey": "PnH1TNoyB37_RsePIaxb3EgAsRpoTwudRuYUXN0d6LY",
      "derivations": {
        "m/0/1/2/3/4/5/6/7/8/9": "C58JmMycJCPVNwjJ3CpTGhME8OlgftJBRTbJauSCBcc",
        "m/68": "Vg3yagfQTGmSQcIdJf-CXdTdHzoVNkugn0rPOeecVR0",
        "m/68/0": "3S8vAvvKSq5jlke0mEyWIiy51vR18C0pRbC5Apbouf0",
        "m/68/0/65": "s1GpWrpuDzkEsa-69xbDRN3FFbvUlwTA1VR9VMP0JHg",
        "m/68/0/65/0": "lNJZvwjZd4Sk-XCAQeYS_IPlfiZdHUV6JDtmC270WhY"
      }
    },
    {
      "desc": "pass-and-qa-generated-by-javascript",
      "cipher": "k6VoY3NiMJKWonB3xBDx_zTiCopvQouZlQhx0FR7zSAAAcQYV0uJNfFEiIks4PSPrb0IKHd6M696wXT7xDHwxfueFSLTbOmD0fb3yrAtK9wjxosnROjZ5cZ2QHE4lV1-A2qffrJHqOmRY6oyIK11maJxYcQQ_qejXfRNJvpcalAxI5en1M0gAAGjcS1ho3EtYqNxLWPEGHmwXwJM1f7N3Q__fP3WAv-jwwzSzkrZP8QxEWWWtrqOuNeH_pyDv-HPX3R1D-5qQmNGqUxCocKAoYPsICZCHdYWNhABa3sIHLc8xsQBgA",
      "unlock": [
        {
          "type": "pwHash",
          "passphrase": "my passphrase with multiple words"
        },
        {
          "type": "securityQuestions",
          "questionList": ["q-a", "q-b", "q-c"],
          "answerList": ["a-a", "a-b", "a-c"]
        }
      ],
      "signPubKey": "CF1utbr3L-wpE0qKwVM5ZNIfyzM6bmplwcU0SM3liqo",
      "derivations": {
        "m/68/0/65/0": "dO7kZSMcSWSQpVEhLmGPS2c3PFid9GtSz0V4m6Vvhlo"
      }
    },
    {
      "desc": "two-pass-generated-by-rust",
      "cipher": "k6VoY3NiMJKWonB3xBC70Y5v4B4DEJ6bZY9ZNeCvzSAAAcQYVQbypAbwQxJMMEYAiKvt9_PbGFCE3nHyxDFlLv9ib9WeDW0wjZFPFtaFW_js2RBfUt34b-MfeUnQ1ZZfe1CAdSZVFuQ_7c8CXp_FlqJwd8QQ2Lf-b-ufVr-1_3heZcDKZc0gAAHEGM7lURX1C40gdwPo_-KIyQCWq8_MVh74SMQxKui_9Aqo_3v8dmDYxdPEe1qHvyguQDuXxxBbLDMoMjzteTTnG_z2SWptfrjQHd6sNcQA",
      "unlock": [
        {
          "type": "pwHash",
          "passphrase": "first-pass"
        },
        {
          "type": "pwHash",
          "passphrase": "second-pass"
        }
      ],
      "signPubKey": "ovEvMUVcDkmcjzk_fjIF8RgOAS2WX40wLLVuqZpZy-o",
      "derivations": {
        "m/68/0/65/0": "GBDlf1xxlanbQcX83w7rCbJkZ8A0ejLPdYddjeQ4dI4"
      }
    },
    {
      "desc": "pass-and-qa-generated-by-rust",
      "cipher": "k6VoY3NiMJKWonB3xBCaTAWCGW9TjLxw4U6jkc-YzSAAAcQYY-56t-6zerft5QuI-G9Z2V8Crd6xIO_pxDHSENNDFJLpCbPE6l64-_RZdSbaAB2EdvwRiZoWONH_o3qgCtCmjfyWPNiKQQpdiyJRmaJxYcQQci5Iy9v5sj1mSOw6MYIV1M0gAAGvRmF2b3JpdGUgQ29sb3I_qkZpcnN0IFBldD-lSGFpcj_EGFGah7pMTe-Iazc5F-jmIvFiPm1TJgZwAsQxv4nlOpAseeZ7b2dcTriyx9AHqwVcRYoM0r2H72jmDYKnac4VApjl1TgUywR_yqX5NcQA",
      "unlock": [
        {
          "type": "pwHash",
          "passphrase": "my passphrase with multiple words"
        },
        {
          "type": "securityQuestions",
          "questionList": ["Favorite Color?", "First Pet?", "Hair?"],
          "answerList": ["\t  BLuE", "ZoMbOrG\t ", " nope "]
        }
      ],
      "signPubKey": "-04bl8RtksINXF5ZZGicrrDEfpxHxQdAirikmTGufIc",
      "derivations": {
        "m/68/0/65/0": "s4FLn5d0UEQqa2YYqO0goC2ITeGGyKvVp9MYAMpSyRg"
      }
    }
  ]
}
