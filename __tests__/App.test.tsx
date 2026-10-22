/**
 * @format
 */

import React from 'react';
import ReactTestRenderer from 'react-test-renderer';
import { Text } from 'react-native';
import App from '../App';

test('renders the app title', async () => {
  let renderer: ReactTestRenderer.ReactTestRenderer | undefined;

  await ReactTestRenderer.act(() => {
    renderer = ReactTestRenderer.create(<App />);
  });

  const texts = renderer!.root
    .findAllByType(Text)
    .map(node => node.props.children)
    .filter((child): child is string => typeof child === 'string');

  expect(texts.length).toBeGreaterThan(0);
  expect(texts).toContain('FIBEMATE Mobile');

  await ReactTestRenderer.act(() => {
    renderer!.unmount();
  });
});
