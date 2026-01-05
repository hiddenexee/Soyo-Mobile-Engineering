setTimeout(function() {
	Java.perform(function() {
		var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		var SSLContext = Java.use('javax.net.ssl.SSLContext');

		var TrustManager = Java.registerClass({
			name: 'dev.asd.test.TrustManager',
			implements: [X509TrustManager],
			methods: {
				checkClientTrusted: function(chain, authType) {},
				checkServerTrusted: function(chain, authType) {},
				getAcceptedIssuers: function() {return []; }
			}
		});

		var TrustManagers = [TrustManager.$new()];
		var SSLContext_init = SSLContext.init.overload(
			'[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
		try {
			SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
				SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
				return;
			};
		} catch (err) {
		}
		try {
			var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
				return;
			};
		} catch(err) {
		}
		try {
			var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
			//okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
			okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(a, b) {
				return;
			};
		} catch(err) {
			//console.log(err);
		}

		try {
			var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
			trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
				//return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var array_list = Java.use("java.util.ArrayList");
			var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
				return array_list.$new();
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			// Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
			var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl_Activity_2.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
				return untrustedChain;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
			appcelerator_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
			fabric_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certChain, authMethod) {
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
			OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
			OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
			phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
				return;
			};
			} catch (err) {
			//console.log(err);
		}
		try {
			var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				//return;
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
			cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
			androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function(type, chain) {
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			// Bypass Squareup CertificatePinner  {1}
			var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}
		try {
			var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				return true;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
			};
		} catch (err) {
			//console.log(err)
		}
		try {
			var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
			};
		} catch (err) {
			//console.log(err)
		}
		try {
			var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(obj1, obj2, obj3, obj4) {
			};
		} catch (err) {
			//console.log(err)
		}
		try {
			var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
			};
		} catch (err) {
			//console.log(err)
		}

		try {
			var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
			CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
				obj3.proceed();
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
			boye_AbstractVerifier.verify.implementation = function(host, ssl) {
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var apache_AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
			apache_AbstractVerifier.verify.implementation = function(a, b, c, d) {
				return;
			};
		} catch (err) {
			//console.log(err);
		}

		try {
			var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
			CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function(a) {
				var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
				return cronet_obj_1;
			};
			CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
				var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
				return cronet_obj_2;
			};
		} catch (err) {
		}

		try {
			var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
			HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
				return true;
			};
		} catch (err) {
		}
		try {
			var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
			SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
				return true;
			};
		} catch (err) {
		}

		function bytesToHex(byteArray) {
			return Array.prototype.map.call(byteArray, function(byte) {
				return ('0' + (byte & 0xFF).toString(16)).slice(-2);
			}).join('');
		}

		Java.perform(function () {
			var Cipher = Java.use("javax.crypto.Cipher");
			var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

			Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {

				try {
					if (params) {
						console.log("[*] Params class: " + params.$className);
						if (IvParameterSpec.class.isInstance(params)) {
							var iv = Java.cast(params, IvParameterSpec).getIV();
						} else {
						}
					} else {
					}
				} catch (e) {
				}

				return this.init(mode, key, params);
			};
		});

		function rudimentaryFix(typeName) {
			if (typeName === undefined){
				return;
			} else if (typeName === 'boolean') {
				return true;
			} else {
				return null;
			}
		}
		try {
			var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
			UnverifiedCertError.$init.implementation = function (str) {
				console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...\x1b[0m');
				try {
					var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
					var exceptionStackIndex = stackTrace.findIndex(stack =>
						stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
					);
					var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
					var className = callingFunctionStack.getClassName();
					var methodName = callingFunctionStack.getMethodName();
					var callingClass = Java.use(className);
					var callingMethod = callingClass[methodName];

					if (callingMethod.implementation) {
						return;
					}

					var returnTypeName = callingMethod.returnType.type;
					callingMethod.implementation = function() {
						rudimentaryFix(returnTypeName);
					};
				} catch (e) {
					if (String(e).includes(".overload")) {
						var splittedList = String(e).split(".overload");
						for (let i=2; i<splittedList.length; i++) {
							var extractedOverload = splittedList[i].trim().split("(")[1].slice(0,-1).replaceAll("'","");
							if (extractedOverload.includes(",")) {
								var argList = extractedOverload.split(", ");
								console.log('\x1b[36m[!] Attempting overload of '+className+'.'+methodName+' with arguments: '+extractedOverload+'\x1b[0m');
								if (argList.length == 2) {
									callingMethod.overload(argList[0], argList[1]).implementation = function(a,b) {
										rudimentaryFix(returnTypeName);
									}
								} else if (argNum == 3) {
									callingMethod.overload(argList[0], argList[1], argList[2]).implementation = function(a,b,c) {
										rudimentaryFix(returnTypeName);
									}
								}  else if (argNum == 4) {
									callingMethod.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function(a,b,c,d) {
										rudimentaryFix(returnTypeName);
									}
								}  else if (argNum == 5) {
									callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function(a,b,c,d,e) {
										rudimentaryFix(returnTypeName);
									}
								}  else if (argNum == 6) {
									callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function(a,b,c,d,e,f) {
										rudimentaryFix(returnTypeName);
									}
								}
							} else {
								callingMethod.overload(extractedOverload).implementation = function(a) {
									rudimentaryFix(returnTypeName);
								}
							}
						}
					} else {
						console.log('\x1b[36m[-] Failed to dynamically patch SSLPeerUnverifiedException '+e+'\x1b[0m');
					}
				}
				return this.$init(str);
			};
		} catch (err) {
			//console.log('\x1b[36m'+err+'\x1b[0m');
		}

	});

}, 3000);

function getC2CMessages(userId, count, lastMessage) {
    return new Promise(function (resolve, reject) {
        try {
            Java.perform(function () {
                var V2TIMManager = Java.use("com.tencent.imsdk.v2.V2TIMManager");
                var manager = V2TIMManager.getInstance();

                var loginStatus = manager.getLoginStatus();
                console.log("SDK Login Status: " + loginStatus);

                if (loginStatus != 1) { // V2TIM_STATUS_LOGINED = 1
                    console.log("SDK henüz giriş yapmamış, durum: " + loginStatus);
                    reject("SDK henüz giriş yapmamış, durum: " + loginStatus);
                    return;
                }

                var messageManager = manager.getMessageManager();

                var V2TIMValueCallback = Java.use("com.tencent.imsdk.v2.V2TIMValueCallback");
                var CallbackImpl = Java.registerClass({
                    name: 'com.frida.C2CMessageCallback' + Math.floor(Math.random() * 100000),
                    implements: [V2TIMValueCallback],
                    methods: {
                        onError: function (errorCode, errorDesc) {
                            console.log("Hata: " + errorCode + " - " + errorDesc);
                            reject("Hata: " + errorCode + " - " + errorDesc);
                        },
                        onSuccess: function (messageList) {
							if (messageList == null) {
								resolve([]);
								return;
							}

							var arrayList = Java.cast(messageList, Java.use("java.util.ArrayList"));
							var size = arrayList.size();

							var results = [];
							for (var i = 0; i < size; i++) {
								try {
									var message = Java.cast(arrayList.get(i), Java.use("com.tencent.imsdk.v2.V2TIMMessage"));
									var elemType = message.getElemType();
									var isSelf = message.isSelf(); //

									if (elemType == 1) { // text
										var textElem = message.getTextElem();
										if (textElem != null) {
											results.push({
												text: textElem.getText(),
												self: isSelf
											});
										}
									}
								} catch (msgError) {
									console.log("Mesaj işlenirken hata: " + msgError);
								}
							}

							resolve(results);
						}
                    }
                });

                var callback = CallbackImpl.$new();
                messageManager.getC2CHistoryMessageList(userId, count || 20, null, callback);
            });
        } catch (error) {
            console.log("Kişisel mesaj alma hatası: " + error);
            reject(error.toString());
        }
    });
}

function sendTextMessage(userId, messageText) {
    Java.perform(function() {
        try {
            var V2TIMManager = Java.use("com.tencent.imsdk.v2.V2TIMManager");
            var manager = V2TIMManager.getInstance();
            var messageManager = manager.getMessageManager();

            var V2TIMSendCallback = Java.use("com.tencent.imsdk.v2.V2TIMSendCallback");

            var CallbackImpl = Java.registerClass({
                name: 'com.frida.CorrectCallback' + Math.floor(Math.random() * 100000),
                implements: [V2TIMSendCallback],
                methods: {
                    onError: function(errorCode, errorDesc) {
                        console.log("[CALLBACK] Hata: " + errorCode + " - " + errorDesc);
                    },
                    onSuccess: function(message) {
                        console.log("[CALLBACK] Başarılı! MSG_ID: " + message.getMsgID());
                    },
                    onProgress: function(progress) {
                        console.log("[CALLBACK] İlerleme: " + progress + "%");
                    }
                }
            });

            var callback = CallbackImpl.$new();
            console.log("[CALLBACK] Callback oluşturuldu");

            var V2TIMOfflinePushInfo = null;
            try {
                V2TIMOfflinePushInfo = Java.use("com.tencent.imsdk.v2.V2TIMOfflinePushInfo");
                console.log("[PUSH_INFO] V2TIMOfflinePushInfo sınıfı alındı");
            } catch (pushError) {
                console.log("[PUSH_INFO] V2TIMOfflinePushInfo alınamadı: " + pushError);
            }

            console.log("[CREATE] Metin mesajı oluşturuluyor...");
            var textMessage = messageManager.createTextMessage(messageText);
            console.log("[CREATE] Metin mesajı oluşturuldu");

            console.log("[SENDING] Doğru parametrelerle gönderiliyor...");
            console.log("[PARAMS] message, receiver=" + userId + ", groupId=null, priority=1, onlineOnly=false, pushInfo=null, callback");

            var sendResult = messageManager.sendMessage(
                textMessage,
                userId,
                null,              // String groupId (null for C2C)
                1,                 // int priority
                false,             // boolean onlineUserOnly
                null,              // V2TIMOfflinePushInfo (null)
                callback           // V2TIMSendCallback
            );

            console.log("[SENT] Gönderim sonucu: " + sendResult);

        } catch (error) {
            console.log("[ERROR] Gönderim hatası: " + error);
            console.log("[STACK] " + error.stack);

            try {
                console.log("\n[DEBUG] sendMessage overload'ları kontrol ediliyor...");
                var V2TIMManager = Java.use("com.tencent.imsdk.v2.V2TIMManager");
                var manager = V2TIMManager.getInstance();
                var messageManager = manager.getMessageManager();

                var sendMessageMethods = messageManager.getClass().getDeclaredMethods();
                console.log("[END_METHODS] sendMessage metodları:");
                for (var i = 0; i < sendMessageMethods.length; i++) {
                    var methodName = sendMessageMethods[i].getName();
                    if (methodName === "sendMessage") {
                        console.log("  - " + sendMessageMethods[i].toString());
                    }
                }
            } catch (debugError) {
                console.log("[DEBUG] Debug hatası: " + debugError);
            }
        }
    });
}

globalThis.getC2CMessages = getC2CMessages;
globalThis.sendTextMessage = sendTextMessage;

rpc.exports = {
    getc2cmessages: getC2CMessages,
	sendtextmessage: sendTextMessage
};
