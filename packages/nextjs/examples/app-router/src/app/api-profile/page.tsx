'use client';

import { useEffect, useState } from 'react';

export default function ApiProfile() {
  const [profile, setProfile] = useState({});

  useEffect(() => {
    const getData = async () => {
      const req = await fetch('/api/profile');
      setProfile(await req.json());
    };

    getData();
  }, []);

  return (
    <div className="mt-5 ml-5">
      <h1 className="text-2xl font-bold mb-4">Api</h1>
      <h2 className="text-xl font-semibold mb-2">User Profile:</h2>
      <pre className="text-sm">{JSON.stringify(profile, undefined, 2)}</pre>
    </div>
  );
}
