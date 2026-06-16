const functions = require("firebase-functions");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

admin.initializeApp();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: functions.config().smtp.user,
    pass: functions.config().smtp.pass,
  },
});

exports.sendAuthOTP = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
        "unauthenticated",
        "User must be signed in.",
    );
  }

  const uid = context.auth.uid;
  const userEmail = context.auth.token.email;
  const ipAddress = context.rawRequest.ip;
  const deviceFingerprint = data.deviceId || "unknown";

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = Date.now() + (10 * 60 * 1000);

  try {
    await admin.firestore().collection("users").doc(uid)
        .collection("security").doc("lockout_status").set({
          currentOtp: otp,
          otpExpiresAt: expiry,
          lastIp: ipAddress,
          lastDeviceId: deviceFingerprint,
          requestedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, {merge: true});

    const mailOptions = {
      from: "ZeroKey Security <noreply@zerokey.app>",
      to: userEmail,
      subject: "Your ZeroKey Security Code",
      text: `Your security code is: ${otp}. It expires in 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    return {success: true};
  } catch (error) {
    console.error("OTP Error:", error);
    throw new functions.https.HttpsError("internal", "Failed to send OTP.");
  }
});