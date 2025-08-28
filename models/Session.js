const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: String,
    duration: String,
    date: String,
    time: { type: String },
    mentor: String,

    // 👇 New mode fields
    mode: {
      type: String,
      enum: ["online", "offline"],
      default: "offline", // by default sessions are online
      required: true,
    },
    meetingLink: {
      type: String,
      // meeting link only makes sense if mode = online
    },
    location: {
      type: String,
      // location only makes sense if mode = offline
    },

    status: {
      type: String,
      enum: ["draft", "published"],
      default: "draft",
    },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // 👇 Registration-related fields
    registeredUsers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    registeredCount: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

// Optional: custom validation to enforce meetingLink vs location
sessionSchema.pre("validate", function (next) {
  if (this.mode === "online" && !this.meetingLink) {
    return next(new Error("Meeting link is required for online sessions"));
  }
  if (this.mode === "offline" && !this.location) {
    return next(new Error("Location is required for offline sessions"));
  }
  next();
});

module.exports = mongoose.model("Session", sessionSchema);
