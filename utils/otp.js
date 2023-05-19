const sgMail = require('@sendgrid/mail')
const pug = require('pug')

sgMail.setApiKey(process.env.SENDGRID_API_KEY)

  exports.sendOTP = async (email, otp) => {
    try {
      const from = `Health <${process.env.EMAIL_FROM}>`;
  
      // Render HTML based on a pug template
      const html = pug.renderFile(`${__dirname}/../mails/verifyAccount.pug`, {
        name: email,
        otp,
        subject: 'Email Subject',
      });
  
      // Define email options
      const mailOptions = {
        from,
        to: email,
        subject: 'Email Subject',
        html,
      };
  
      console.log('Sending OTP email:', mailOptions);
  
      await sgMail.send(mailOptions);
  
      console.log('OTP email sent');
    } catch (error) {
      console.error('Failed to send OTP:', error);
      throw new Error('Failed to send OTP');
    }
  };